package eu.kanade.tachiyomi.extension.ar.procomic

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Rect
import android.util.Base64
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.model.SMangaUpdate
import keiyoushi.annotation.Source
import keiyoushi.network.get
import keiyoushi.network.rateLimit
import keiyoushi.source.KeiSource
import keiyoushi.utils.asJsoup
import keiyoushi.utils.parseAs
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@Source
abstract class ProComic : KeiSource() {

    private val apiUrl = "$baseUrl/api"

    override val supportsLatest = true

    override fun Headers.Builder.configureHeaders() = apply {
        add("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
        add("Accept-Language", "ar,en;q=0.8")
        add("Referer", "$baseUrl/")
    }

    override fun OkHttpClient.Builder.configureClient() = rateLimit(2).addInterceptor(ProComicMapInterceptor(this@ProComic))

    override suspend fun getPopularManga(page: Int): MangasPage = getContentPage(page, "popular")

    override suspend fun getLatestUpdates(page: Int): MangasPage = getContentPage(page, "latest")

    override suspend fun getSearchMangaList(
        page: Int,
        query: String,
        filters: FilterList,
    ): MangasPage {
        val url = apiUrl.toHttpUrl().newBuilder()
            .addPathSegment("content")
            .addQueryParameter("page", page.toString())
            .addQueryParameter("limit", PAGE_SIZE.toString())
            .apply {
                if (query.isNotBlank()) addQueryParameter("search", query)
            }
            .build()

        return client.get(url).parseAs<ContentPageDto>().toMangasPage()
    }

    override suspend fun getMangaByUrl(url: HttpUrl): SManga? {
        val contentId = url.pathSegments.lastOrNull()
            ?.substringAfterLast("-")
            ?.toIntOrNull()
            ?: return null

        return client.get("$apiUrl/content/$contentId").parseAs<ContentDto>().toSManga()
    }

    override suspend fun fetchMangaUpdate(
        manga: SManga,
        chapters: List<SChapter>,
        fetchDetails: Boolean,
        fetchChapters: Boolean,
    ): SMangaUpdate {
        val contentId = manga.url.substringAfterLast("-").toIntOrNull() ?: return SMangaUpdate(manga, chapters)
        val content = client.get("$apiUrl/content/$contentId").parseAs<ContentDto>()

        val details = if (fetchDetails) content.toSManga(manga.url) else manga
        val chapterList = if (fetchChapters) getAllChapters(content, manga.url) else chapters

        return SMangaUpdate(details, chapterList)
    }

    override suspend fun getPageList(chapter: SChapter): List<Page> {
        val document = client.get("$baseUrl${chapter.url}".toHttpUrl()).asJsoup()
        // نجمع كل محتوى وسوم <script> بنص واحد متواصل أولاً، عشان روابط الصور
        // المقطوعة بين وسمين متتاليين تتلزّق وتصير قابلة للمطابقة الكاملة.
        val payload = document.select("script").joinToString(separator = "") { it.html() }

        val pageUrls = APP_IMAGE_REGEX.findAll(payload)
            .map { it.value }
            .distinct()
            .toList()

        val pages = pageUrls.mapIndexed { index, imageUrl ->
            Page(index, imageUrl = imageUrl)
        }.toMutableList()

        // ============================================================
        // دعم الصفحات المؤجلة (deferredMedia): بعض الفصول تحمّل فقط أول
        // splitIndex صورة داخل HTML الأولي، والباقي يحتاج طلب إضافي +
        // فك تشفير AES-GCM + تجميع قطع (jigsaw) عبر ProComicMapInterceptor.
        //
        // ملاحظة مهمة: نص الـ RSC داخل <script> يأتي مُهرَّبًا (escaped) لأنه
        // جزء من نص JavaScript (self.__next_f.push([1,"..."]))؛ علامات
        // الاقتباس تظهر كـ \" بدل ". نفكّ التهريب هنا قبل تطبيق الـ regex.
        // ============================================================
        val unescapedPayload = payload.replace("\\\"", "\"")
        val chapterId = chapter.url.substringAfterLast("-").toLongOrNull()
        val deferredBlock = DEFERRED_MEDIA_REGEX.find(unescapedPayload)?.groupValues?.get(1)
        val deferredToken = deferredBlock?.let { TOKEN_REGEX.find(it)?.groupValues?.get(1) }

        if (chapterId != null && deferredToken != null) {
            val splitIndex = deferredBlock
                ?.let { SPLIT_INDEX_REGEX.find(it)?.groupValues?.get(1)?.toIntOrNull() }
                ?: pages.size

            try {
                val deferredData = fetchDeferredMedia(
                    client = client,
                    json = lenientJson,
                    baseUrl = baseUrl,
                    chapterId = chapterId,
                    deferredToken = deferredToken,
                    splitIndex = splitIndex,
                )

                // صور إضافية: أحيانًا ترجع كروابط كاملة، وأحيانًا كمسارات نسبية
                // (بدون host) تحتاج نفس آلية التوقيع اللي تحتاجها القطع المشفّرة.
                // نمررها كلها عبر الـ Interceptor لضمان توقيعها الصحيح قبل الجلب.
                if (deferredData.images.isNotEmpty()) {
                    ProComicImageCache.store(chapterId, deferredData.images)
                    deferredData.images.indices.forEach { imageIndex ->
                        val internalUrl = "https://$PROCOMIC_IMAGE_HOST/$chapterId/$imageIndex"
                        pages.add(Page(pages.size, imageUrl = internalUrl))
                    }
                }

                // خرائط محمية تحتاج فك تشفير وتجميع قطع؛ نخزّنها بذاكرة مؤقتة
                // ونضيف صفحات وهمية تشير للـ Interceptor بدل رابط صورة مباشر.
                if (deferredData.maps.isNotEmpty()) {
                    ProComicMapCache.store(chapterId, deferredData.maps)
                    deferredData.maps.indices.forEach { mapIndex ->
                        val internalUrl = "https://$PROCOMIC_MAP_HOST/$chapterId/$mapIndex"
                        pages.add(Page(pages.size, imageUrl = internalUrl))
                    }
                }
            } catch (e: Exception) {
                // فشل جلب الوسائط المؤجلة لا يجب أن يمنع عرض الصفحات المتوفرة أصلًا.
            }
        }

        return pages
    }

    override fun getMangaUrl(manga: SManga): String = "$baseUrl/ar/${manga.url}"

    override fun getChapterUrl(chapter: SChapter): String = "$baseUrl${chapter.url}"

    override fun getFilterList(data: JsonElement?) = FilterList()

    private suspend fun getContentPage(page: Int, sort: String): MangasPage {
        val url = apiUrl.toHttpUrl().newBuilder()
            .addPathSegment("content")
            .addQueryParameter("page", page.toString())
            .addQueryParameter("limit", PAGE_SIZE.toString())
            .addQueryParameter("sort", sort)
            .build()

        return client.get(url).parseAs<ContentPageDto>().toMangasPage()
    }

    private suspend fun getAllChapters(content: ContentDto, mangaUrl: String): List<SChapter> {
        val apiType = content.type.lowercase()
        if (apiType !in SUPPORTED_TYPES) return emptyList()

        val firstPage = getChapterPage(apiType, content.id, 1)
        val pageCount = (firstPage.total + PAGE_SIZE - 1) / PAGE_SIZE
        val pages = buildList {
            add(firstPage)
            for (page in 2..pageCount) {
                add(getChapterPage(apiType, content.id, page))
            }
        }

        val seriesSlug = mangaUrl.substringBeforeLast("-")
        return pages.asSequence()
            .flatMap { it.data.asSequence() }
            .filter { it.language.equals("AR", ignoreCase = true) }
            .distinctBy { it.id }
            .map { it.toSChapter(seriesSlug) }
            .toList()
    }

    private suspend fun getChapterPage(type: String, contentId: Int, page: Int): ChapterPageDto {
        val url = apiUrl.toHttpUrl().newBuilder()
            .addPathSegment(type)
            .addPathSegment(contentId.toString())
            .addPathSegment("chapters")
            .addQueryParameter("page", page.toString())
            .addQueryParameter("limit", PAGE_SIZE.toString())
            .build()

        return client.get(url).parseAs()
    }

    private fun ContentPageDto.toMangasPage(): MangasPage {
        val mangas = data.asSequence()
            .filter { it.type.lowercase() in SUPPORTED_TYPES }
            .map { it.toSManga() }
            .toList()

        return MangasPage(mangas, meta.page < meta.pages)
    }

    private fun JsonElement?.asStringList(): List<String> = when (this) {
        null -> emptyList()
        is JsonArray -> mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        is JsonPrimitive -> contentOrNull?.let { listOf(it) } ?: emptyList()
        else -> emptyList()
    }

    private fun ContentDto.toSManga(url: String = "$slug-$id") = SManga.create().apply {
        this.url = url
        title = this@toSManga.title
        description = metadata?.descriptions?.get("ar") ?: description
        author = metadata?.author.asStringList().joinToString().ifBlank { null }
        artist = metadata?.artist.asStringList().joinToString().ifBlank { null }
        genre = metadata?.genres?.joinToString()
        thumbnail_url = thumbnail
        status = when {
            progress.contains("مستمر") -> SManga.ONGOING
            progress.contains("مكتمل") -> SManga.COMPLETED
            else -> SManga.UNKNOWN
        }
    }

    private fun ChapterDto.toSChapter(seriesSlug: String) = SChapter.create().apply {
        val number = chapterNumber.trim()
        url = "/ar/chapter/$seriesSlug-$number-$id"
        name = "الفصل $number"
        chapter_number = number.toFloatOrNull() ?: 0f
        date_upload = publishedAt?.let { runCatching { Instant.parse(it).toEpochMilli() }.getOrNull() } ?: 0L
        scanlator = translator
    }

    @Serializable
    private class ContentPageDto(
        val data: List<ContentDto> = emptyList(),
        val meta: PageMetaDto = PageMetaDto(),
    )

    @Serializable
    private class PageMetaDto(
        val page: Int = 1,
        val pages: Int = 1,
    )

    @Serializable
    private class ContentDto(
        val id: Int,
        val title: String,
        val slug: String,
        val description: String? = null,
        val type: String,
        val progress: String = "",
        val thumbnail: String? = null,
        val metadata: ContentMetadataDto? = null,
    )

    @Serializable
    private class ContentMetadataDto(
        val author: JsonElement? = null,
        val artist: JsonElement? = null,
        val genres: List<String> = emptyList(),
        val descriptions: Map<String, String> = emptyMap(),
    )

    @Serializable
    private class ChapterPageDto(
        val data: List<ChapterDto> = emptyList(),
        val total: Int = 0,
    )

    @Serializable
    private class ChapterDto(
        val id: Int,
        @SerialName("chapter_number")
        val chapterNumber: String,
        val language: String = "",
        val translator: String? = null,
        @SerialName("published_at")
        val publishedAt: String? = null,
    )

    private companion object {
        const val PAGE_SIZE = 100
        val SUPPORTED_TYPES = setOf("manga", "manhua", "manhwa")
        val APP_IMAGE_REGEX = Regex("""https://app\.procomic\.pro/chapters/[^"\\\s]+""")

        // ثوابت استخراج بيانات الوسائط المؤجلة (deferredMedia) من RSC payload
        val DEFERRED_MEDIA_REGEX = Regex(""""deferredMedia":\{([^{}]*)\}""")
        val TOKEN_REGEX = Regex(""""token":"([^"]+)"""")
        val SPLIT_INDEX_REGEX = Regex(""""splitIndex":(\d+)""")
    }
}

// ============================================================
// آلية جلب وفك تشفير صفحات الفصول المؤجلة (deferred media) لموقع procomic.pro.
//
// الطريقة كاملة (مستخرجة من ملف page-70d29726605443ff.js عبر تحليل الجافاسكربت):
// 1. الصفحة الأولية تحتوي على deferredMedia.token (JWT موقّع، ليس مشفّرًا) و splitIndex.
// 2. GET /chapter-deferred-media/{chapterId}?token={token}&split={splitIndex}
//    يرجع { data: { images: [...], maps: [...] } }
// 3. كل عنصر بـ maps[] له "token" (base64url JSON) يحتوي v, m, cid, iv, tag, data
// 4. حسب "m":
//    - "browser"          -> المفتاح = SHA-256("prochan-browser-map:" + STATIC_SALT + ":" + chapterId)
//    - "browser_session"  -> المفتاح يُجلب من GET /chapter-map-session-key/{chapterId}?legacy=1
// 5. فك تشفير AES-GCM(key, iv, data+tag) -> JSON فيه dim, mode, pieces, order
// 6. تجميع القطع (pieces) بترتيبها الصحيح (order) على Bitmap واحد حسب mode.
// 7. قطع الصور المحمية على cdn2.procomic.pro تحتاج توقيع قبل التنزيل عبر
//    POST /api/cdn-image/sign ثم GET /api/cdn-image?expires=..&token=..&url=..
//
// getImage(page) بـ HttpSource نهائية (final) ولا يمكن استبدالها، لذلك نضيف
// Interceptor مخصص على مستوى OkHttpClient يعترض روابط داخلية وهمية
// (procomic-map.internal) ويبني الصورة يدويًا بدل إرسال طلب فعلي لها.
// ============================================================

private const val STATIC_SALT =
    "2e6f9a1c4d8b7e3f0a5c9d2b6e1f4a8c7d3b0e6a9f2c5d8b1e4a7c0d3f6b9e2"

private const val GCM_TAG_LENGTH_BYTES = 16
private const val GCM_TAG_LENGTH_BITS = GCM_TAG_LENGTH_BYTES * 8

/**
 * Json متساهل يتجاهل أي حقول إضافية غير متوقعة بردود الخادم (مثل حقول حماية
 * أو تتبّع إضافية لم تُوثَّق بتحليل الجافاسكربت الأصلي). استخدام jsonInstance
 * الافتراضي (الصارم) يتسبب برمي استثناء فوري لو ظهر حقل جديد، بدون أي طلب
 * شبكة إضافي — وهذا بالضبط ما كان يفشل بصفحات "الوسائط المؤجلة" المحمية.
 */
private val lenientJson = Json { ignoreUnknownKeys = true }

const val PROCOMIC_MAP_HOST = "procomic-map.internal"
const val PROCOMIC_IMAGE_HOST = "procomic-image.internal"

@Serializable
data class DeferredMediaEnvelope(
    val success: Boolean = true,
    val data: DeferredMediaData? = null,
)

@Serializable
data class DeferredMediaData(
    val chapterId: Long = 0,
    val splitIndex: Int = 0,
    val images: List<String> = emptyList(),
    val maps: List<MapEntry> = emptyList(),
    val source: String? = null,
)

@Serializable
data class MapEntry(
    val token: String,
    val method: String? = null,
)

/** محتوى الـ token الداخلي بعد فك ترميز base64url (قبل فك التشفير) */
@Serializable
data class ReconstructionEnvelope(
    val v: Int,
    val m: String,
    val cid: JsonElement,
    val iv: String,
    val tag: String,
    val data: String,
)

/** الخريطة النهائية بعد فك التشفير */
@Serializable
data class ReconstructionMap(
    val dim: List<Int>,
    val mode: String,
    val pieces: List<String>,
    val order: List<Int>,
    val rects: List<PieceRect>? = null,
)

@Serializable
data class PieceRect(
    val left: Int,
    val top: Int,
    val width: Int,
    val height: Int,
)

@Serializable
data class SessionKeyEnvelope(
    val success: Boolean = true,
    val data: SessionKeyData? = null,
)

@Serializable
data class SessionKeyData(
    val key: String,
    val expiresAt: Long,
    val viewerToken: String? = null,
    val viewerTokenExpiresAt: Long? = null,
    val viewerWatermark: JsonElement? = null,
)

private fun decodeBase64Url(input: String): ByteArray {
    val normalized = input.replace('-', '+').replace('_', '/')
    val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
    return Base64.decode(padded, Base64.DEFAULT)
}

/** GET /chapter-deferred-media/{chapterId}?token={token}&split={splitIndex} */
fun fetchDeferredMedia(
    client: OkHttpClient,
    json: Json,
    baseUrl: String,
    chapterId: Long,
    deferredToken: String,
    splitIndex: Int,
): DeferredMediaData = retrying {
    val url = "$baseUrl/chapter-deferred-media/$chapterId" +
        "?token=${URLEncoder.encode(deferredToken, "UTF-8")}" +
        "&split=$splitIndex"

    val request = Request.Builder()
        .url(url)
        .header("Accept", "application/json")
        .header("Referer", "$baseUrl/")
        .header("Origin", baseUrl)
        .build()

    client.newCall(request).execute().use { response ->
        if (!response.isSuccessful) {
            throw Exception("Failed to fetch chapter-deferred-media: HTTP ${response.code}")
        }
        val body = response.body?.string().orEmpty()
        val envelope = json.decodeFromString(DeferredMediaEnvelope.serializer(), body)
        envelope.data ?: DeferredMediaData()
    }
}

fun parseReconstructionEnvelope(json: Json, mapEntry: MapEntry): ReconstructionEnvelope {
    val decoded = decodeBase64Url(mapEntry.token)
    val text = String(decoded, Charsets.UTF_8)
    return json.decodeFromString(ReconstructionEnvelope.serializer(), text)
}

/** الطريقة "browser": مفتاح مشتق محليًا، بدون أي طلب شبكة */
fun deriveBrowserKey(chapterId: Long): SecretKeySpec {
    val material = "prochan-browser-map:$STATIC_SALT:$chapterId"
    val digest = MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.UTF_8))
    return SecretKeySpec(digest, "AES")
}

/**
 * الطريقة "browser_session": يجلب المفتاح الخام (base64url) من الخادم.
 * GET /chapter-map-session-key/{chapterId}?legacy=1
 */
fun fetchSessionKey(
    client: OkHttpClient,
    json: Json,
    baseUrl: String,
    chapterId: Long,
): SecretKeySpec = retrying {
    val url = "$baseUrl/chapter-map-session-key/$chapterId?legacy=1"

    val request = Request.Builder()
        .url(url)
        .header("Accept", "application/json")
        .header("Referer", "$baseUrl/")
        .header("Origin", baseUrl)
        .build()

    client.newCall(request).execute().use { response ->
        if (!response.isSuccessful) {
            throw Exception("Failed to fetch chapter-map-session-key: HTTP ${response.code}")
        }
        val body = response.body?.string().orEmpty()
        val envelope = json.decodeFromString(SessionKeyEnvelope.serializer(), body)
        val rawKey = envelope.data?.key
            ?: throw Exception("chapter-map-session-key response missing 'key'")
        val keyBytes = decodeBase64Url(rawKey)
        SecretKeySpec(keyBytes, "AES")
    }
}

fun decryptReconstructionMap(
    json: Json,
    envelope: ReconstructionEnvelope,
    key: SecretKeySpec,
): ReconstructionMap {
    val iv = decodeBase64Url(envelope.iv)
    val tag = decodeBase64Url(envelope.tag)
    val cipherTextOnly = decodeBase64Url(envelope.data)
    val cipherTextWithTag = cipherTextOnly + tag

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
    cipher.init(Cipher.DECRYPT_MODE, key, spec)

    val plainBytes = cipher.doFinal(cipherTextWithTag)
    val plainText = String(plainBytes, Charsets.UTF_8)

    return json.decodeFromString(ReconstructionMap.serializer(), plainText)
}

/**
 * دالة مساعدة تجمع كل الخطوات السابقة لعنصر map واحد.
 * chapterId هنا يجب أن يطابق cid المرمّز داخل الـ token (تحقق أمان).
 */
fun resolveMapEntry(
    client: OkHttpClient,
    json: Json,
    baseUrl: String,
    chapterId: Long,
    mapEntry: MapEntry,
): ReconstructionMap {
    val envelope = parseReconstructionEnvelope(json, mapEntry)

    val key = when (envelope.m) {
        "browser" -> deriveBrowserKey(chapterId)
        "browser_session" -> ProComicSessionKeyCache.getOrFetch(chapterId) {
            fetchSessionKey(client, json, baseUrl, chapterId)
        }
        else -> throw Exception("Unsupported reconstruction map method: ${envelope.m}")
    }

    return decryptReconstructionMap(json, envelope, key)
}

/**
 * يحسب مواقع القطع بناءً على "mode" بنفس منطق الجافاسكربت الأصلي.
 * الصيغ المتوقعة: "grid_{cols}x{rows}", "vertical_{n}", "horizontal_{n}"
 */
fun computePieceRects(map: ReconstructionMap): List<PieceRect> {
    map.rects?.let { if (it.size == map.order.size) return it }

    val width = map.dim.getOrElse(0) { 1 }.coerceAtLeast(1)
    val height = map.dim.getOrElse(1) { 1 }.coerceAtLeast(1)
    val pieceCount = if (map.order.isNotEmpty()) map.order.size else map.pieces.size

    val parts = map.mode.split("_")
    val kind = parts.getOrElse(0) { "vertical" }
    val param = parts.getOrElse(1) { "1" }

    if (kind == "grid") {
        val (colsStr, rowsStr) = param.split("x").let { it.getOrElse(0) { "1" } to it.getOrElse(1) { "1" } }
        val cols = colsStr.toIntOrNull()?.coerceAtLeast(1) ?: 1
        val rows = rowsStr.toIntOrNull()?.coerceAtLeast(1) ?: 1

        val baseColWidth = width / cols
        val baseRowHeight = height / rows
        val extraCols = width - baseColWidth * cols
        val extraRows = height - baseRowHeight * rows

        val colWidths = IntArray(cols) { i -> (baseColWidth + if (i < extraCols) 1 else 0).coerceAtLeast(1) }
        val rowHeights = IntArray(rows) { i -> (baseRowHeight + if (i < extraRows) 1 else 0).coerceAtLeast(1) }

        val colOffsets = IntArray(cols)
        var acc = 0
        for (i in 0 until cols) {
            colOffsets[i] = acc
            acc += colWidths[i]
        }

        val rowOffsets = IntArray(rows)
        acc = 0
        for (i in 0 until rows) {
            rowOffsets[i] = acc
            acc += rowHeights[i]
        }

        return List(pieceCount) { index ->
            val col = index % cols
            val row = index / cols
            PieceRect(
                left = colOffsets.getOrElse(col) { 0 },
                top = rowOffsets.getOrElse(row) { 0 },
                width = colWidths.getOrElse(col) { width },
                height = rowHeights.getOrElse(row) { height },
            )
        }
    }

    val segments = if (kind == "vertical") param.toIntOrNull()?.coerceAtLeast(1) ?: pieceCount else pieceCount
    val total = if (kind == "vertical") width else height
    val baseSize = total / segments
    val extra = total - baseSize * segments
    val sizes = IntArray(segments) { i -> (baseSize + if (i < extra) 1 else 0).coerceAtLeast(1) }
    val offsets = IntArray(segments)
    var acc2 = 0
    for (i in 0 until segments) {
        offsets[i] = acc2
        acc2 += sizes[i]
    }

    return List(pieceCount) { index ->
        if (kind == "vertical") {
            PieceRect(
                left = offsets.getOrElse(index) { 0 },
                top = 0,
                width = sizes.getOrElse(index) { width },
                height = height,
            )
        } else {
            PieceRect(
                left = 0,
                top = offsets.getOrElse(index) { 0 },
                width = width,
                height = sizes.getOrElse(index) { height },
            )
        }
    }
}

private const val CDN2_HOST_MARKER = "cdn2.procomic.pro"

/**
 * يعيد تنفيذ [block] عدة مرات لو رمى استثناء، مع تأخير بسيط بينها.
 *
 * السبب: بعض فشل تحميل الصفحات ليس خطأ منطقي ثابت، بل فشل شبكي مؤقت (مهلة
 * اتصال، أو رفض عابر من الخادم بسبب تزامن عدة طلبات توقيع/تنزيل قطع بنفس
 * اللحظة عند تحميل Mihon لعدة صفحات بالتوازي). إعادة المحاولة تلقائيًا تحل
 * أغلب هذي الحالات بدل ما تفشل الصفحة نهائيًا من أول عثرة.
 */
private fun <T> retrying(times: Int = 3, delayMs: Long = 350, block: (attempt: Int) -> T): T {
    var lastError: Exception? = null
    for (attempt in 1..times) {
        try {
            return block(attempt)
        } catch (e: Exception) {
            lastError = e
            if (attempt < times) {
                Thread.sleep(delayMs * attempt)
            }
        }
    }
    throw lastError ?: Exception("Unknown error after $times attempts")
}

/**
 * يوقّع رابط cdn2:
 * POST /api/cdn-image/sign { "url": rawCdn2Url } -> { token, expires }
 * ثم يبني الرابط النهائي: /api/cdn-image?expires=..&token=..&url=..
 */
fun buildSignedImageUrl(
    client: OkHttpClient,
    json: Json,
    baseUrl: String,
    rawUrl: String,
): String {
    if (CDN2_HOST_MARKER !in rawUrl) return rawUrl

    return retrying {
        val payload = """{"url":"$rawUrl"}"""
        val signRequest = Request.Builder()
            .url("$baseUrl/api/cdn-image/sign")
            .header("Referer", "$baseUrl/")
            .header("Origin", baseUrl)
            .post(payload.toRequestBody("application/json".toMediaType()))
            .build()

        client.newCall(signRequest).execute().use { response ->
            if (!response.isSuccessful) {
                throw Exception("cdn-image/sign failed: HTTP ${response.code}")
            }
            val body = response.body?.string().orEmpty()
            val parsed = json.parseToJsonElement(body)
            val jsonObj = parsed as? JsonObject ?: throw Exception("Invalid sign response")

            val tokenElement = jsonObj["token"] as? JsonPrimitive
            val token = tokenElement?.content ?: throw Exception("Sign response missing token")

            val expiresElement = jsonObj["expires"] as? JsonPrimitive
            val expires = expiresElement?.content ?: throw Exception("Sign response missing expires")

            val encodedUrl = URLEncoder.encode(rawUrl, "UTF-8")
            "$baseUrl/api/cdn-image?expires=$expires&token=$token&url=$encodedUrl"
        }
    }
}

/** يحل رابط قطعة نسبي إلى رابط مطلق كامل، إذا لزم الأمر */
fun resolvePieceUrl(baseUrl: String, rawPiece: String, cdnPath: String?): String {
    if (rawPiece.startsWith("http://") || rawPiece.startsWith("https://")) {
        return rawPiece
    }

    // نعطي الأولوية لبادئة cdnPath (مثل cdn2.procomic.pro) بغض النظر عن وجود
    // شرطة مائلة بأول المسار؛ مسارات القطع/الصور المحمية دائمًا على الـ CDN،
    // وليست مسارات نسبية على procomic.pro نفسه.
    val trimmedPiece = rawPiece.trimStart('/')

    if (!cdnPath.isNullOrBlank()) {
        return if (cdnPath.contains(".")) {
            "https://$cdnPath/$trimmedPiece"
        } else {
            "https://$cdnPath.procomic.pro/$trimmedPiece"
        }
    }

    if (rawPiece.startsWith("/")) {
        return baseUrl.trimEnd('/') + rawPiece
    }

    return rawPiece
}

private fun downloadPieceBitmap(client: OkHttpClient, url: String): Bitmap = retrying {
    val request = Request.Builder().url(url).build()
    client.newCall(request).execute().use { response ->
        if (!response.isSuccessful) throw Exception("Failed to download piece: HTTP ${response.code} ($url)")
        val bytes = response.body?.bytes() ?: throw Exception("Empty piece body ($url)")
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            ?: throw Exception("Failed to decode piece bitmap ($url)")
    }
}

/**
 * يجمّع كل القطع بترتيبها الصحيح (map.order) على Bitmap نهائي واحد،
 * ثم يرجعه كـ JPEG bytes جاهز للإرسال كـ Response لـ Mihon.
 */
fun assembleReconstructedImage(
    client: OkHttpClient,
    baseUrl: String,
    map: ReconstructionMap,
    cdnPath: String?,
): ByteArray {
    val width = map.dim.getOrElse(0) { 1 }.coerceAtLeast(1)
    val height = map.dim.getOrElse(1) { 1 }.coerceAtLeast(1)
    val rects = computePieceRects(map)

    val finalBitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(finalBitmap)

    map.order.forEachIndexed { positionIndex, pieceIndex ->
        val rawPieceUrl = map.pieces.getOrNull(pieceIndex)
            ?: throw Exception("Missing piece at index $pieceIndex")

        val resolvedUrl = resolvePieceUrl(baseUrl, rawPieceUrl, cdnPath)
        val finalUrl = buildSignedImageUrlSafely(client, baseUrl, resolvedUrl)

        val pieceBitmap = downloadPieceBitmap(client, finalUrl)
        val rect = rects.getOrNull(positionIndex)
            ?: throw Exception("Missing rect for position $positionIndex")

        val destRect = Rect(rect.left, rect.top, rect.left + rect.width, rect.top + rect.height)
        canvas.drawBitmap(pieceBitmap, null, destRect, null)
        pieceBitmap.recycle()
    }

    val output = ByteArrayOutputStream()
    finalBitmap.compress(Bitmap.CompressFormat.JPEG, 92, output)
    finalBitmap.recycle()
    return output.toByteArray()
}

/** يوقّع الرابط فقط لو محتاج توقيع، بدون تفجير الاستثناء لو فشل التوقيع */
private fun buildSignedImageUrlSafely(client: OkHttpClient, baseUrl: String, url: String): String = try {
    val json = Json { ignoreUnknownKeys = true }
    buildSignedImageUrl(client, json, baseUrl, url)
} catch (e: Exception) {
    url
}

/**
 * ذاكرة مؤقتة لتخزين maps[] الخاصة بكل فصل، بحيث يقدر الـ Interceptor
 * يوصل لها لاحقًا وقت تحميل كل صورة.
 */
object ProComicMapCache {
    private val cache = ConcurrentHashMap<Long, List<MapEntry>>()

    fun store(chapterId: Long, maps: List<MapEntry>) {
        cache[chapterId] = maps
    }

    fun get(chapterId: Long, mapIndex: Int): MapEntry? = cache[chapterId]?.getOrNull(mapIndex)
}

/**
 * ذاكرة مؤقتة لتخزين روابط الصور الإضافية (deferredMedia.images) الخاصة بكل
 * فصل. بعض الفصول ترجع هذي الروابط كمسارات نسبية بدون host، فتحتاج تمريرها
 * عبر resolvePieceUrl + آلية التوقيع قبل الجلب الفعلي، بدل استخدامها مباشرة.
 */
object ProComicImageCache {
    private val cache = ConcurrentHashMap<Long, List<String>>()

    fun store(chapterId: Long, images: List<String>) {
        cache[chapterId] = images
    }

    fun get(chapterId: Long, imageIndex: Int): String? = cache[chapterId]?.getOrNull(imageIndex)
}

/**
 * ذاكرة مؤقتة لمفتاح جلسة "browser_session" لكل فصل.
 *
 * المشكلة اللي تحلّها: Mihon يحمّل عدة صفحات بالتوازي، وكل صفحة كانت (قبل هذا
 * الإصلاح) ترسل طلبها الخاص لـ GET /chapter-map-session-key/{chapterId} —
 * يعني فصل فيه 17 صفحة محمية يرسل 17 طلب متزامن لنفس الـ endpoint. الخادم
 * على الأغلب يعامل المفتاح كمفتاح جلسة صالح لاستخدام واحد أو يرفض الطلبات
 * المتكررة/المتزامنة، وهذا يفسّر النمط الملحوظ: أول صفحة أو صفحتين تنجحان ثم
 * تفشل أغلب الباقي بـ HTTP 500.
 *
 * الحل: نجلب المفتاح مرة واحدة فقط لكل chapterId ونعيد استخدام نفس النسخة
 * لكل صفحات نفس الفصل. الـ synchronized على قفل خاص بكل فصل يضمن إنه لو
 * وصلت عدة صفحات بنفس اللحظة (تحميل متوازي)، أول وحدة بس ترسل الطلب الفعلي
 * والباقي ينتظر ويستخدم النتيجة المخزَّنة بدل تكرار الطلب.
 */
object ProComicSessionKeyCache {
    private val cache = ConcurrentHashMap<Long, SecretKeySpec>()
    private val locks = ConcurrentHashMap<Long, Any>()

    fun getOrFetch(chapterId: Long, fetch: () -> SecretKeySpec): SecretKeySpec {
        cache[chapterId]?.let { return it }
        val lock = locks.getOrPut(chapterId) { Any() }
        synchronized(lock) {
            cache[chapterId]?.let { return it }
            val key = fetch()
            cache[chapterId] = key
            return key
        }
    }
}

/**
 * يعترض الطلبات لروابط procomic-map.internal و procomic-image.internal فقط،
 * ويترك أي طلب آخر يمر بشكل طبيعي.
 */
class ProComicMapInterceptor(private val source: ProComic) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val url = request.url

        return when (url.host) {
            PROCOMIC_MAP_HOST -> interceptMap(request, url)
            PROCOMIC_IMAGE_HOST -> interceptImage(request, url)
            else -> chain.proceed(request)
        }
    }

    private fun interceptMap(request: Request, url: HttpUrl): Response {
        val chapterId = url.pathSegments.getOrNull(0)?.toLongOrNull()
        val mapIndex = url.pathSegments.getOrNull(1)?.toIntOrNull()

        val mapEntry = if (chapterId != null && mapIndex != null) {
            ProComicMapCache.get(chapterId, mapIndex)
        } else {
            null
        }

        if (chapterId == null || mapEntry == null) {
            return errorResponse(request, 404, "Protected page map not found in cache")
        }

        return try {
            val reconstructionMap = resolveMapEntry(
                client = source.client,
                json = lenientJson,
                baseUrl = source.baseUrl,
                chapterId = chapterId,
                mapEntry = mapEntry,
            )
            val imageBytes = assembleReconstructedImage(
                client = source.client,
                baseUrl = source.baseUrl,
                map = reconstructionMap,
                cdnPath = "cdn2",
            )

            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(imageBytes.toResponseBody("image/jpeg".toMediaType()))
                .build()
        } catch (e: Exception) {
            diagnosticImageResponse(request, "MAP #${mapEntry.method}: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun interceptImage(request: Request, url: HttpUrl): Response {
        val chapterId = url.pathSegments.getOrNull(0)?.toLongOrNull()
        val imageIndex = url.pathSegments.getOrNull(1)?.toIntOrNull()

        val rawImage = if (chapterId != null && imageIndex != null) {
            ProComicImageCache.get(chapterId, imageIndex)
        } else {
            null
        }

        if (rawImage == null) {
            return errorResponse(request, 404, "Protected image not found in cache")
        }

        return try {
            val resolvedUrl = resolvePieceUrl(source.baseUrl, rawImage, "cdn2")
            val signedUrl = buildSignedImageUrlSafely(source.client, source.baseUrl, resolvedUrl)

            retrying { attempt ->
                val imageRequest = Request.Builder()
                    .url(signedUrl)
                    .header("Referer", "${source.baseUrl}/")
                    .build()

                source.client.newCall(imageRequest).execute().use { upstream ->
                    if (!upstream.isSuccessful) {
                        throw Exception("upstream image fetch failed: HTTP ${upstream.code} (attempt $attempt)")
                    }
                    val bytes = upstream.body?.bytes() ?: ByteArray(0)
                    val contentType = upstream.header("Content-Type") ?: "image/avif"

                    Response.Builder()
                        .request(request)
                        .protocol(Protocol.HTTP_1_1)
                        .code(200)
                        .message("OK")
                        .body(bytes.toResponseBody(contentType.toMediaType()))
                        .build()
                }
            }
        } catch (e: Exception) {
            diagnosticImageResponse(request, "IMAGE: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun errorResponse(request: Request, code: Int, message: String): Response = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message(message)
        .body(ByteArray(0).toResponseBody(null))
        .build()

    /**
     * بدل كرت خطأ Mihon العام ("HTTP 500")، نرسم النص الحقيقي للاستثناء داخل
     * صورة JPEG صالحة (كود 200) بحيث يقدر المستخدم يشوفه مباشرة بدون أي أدوات
     * تشخيص إضافية (logcat/PCAPdroid). يُستخدم فقط بعد استنفاد كل محاولات
     * إعادة المحاولة التلقائية.
     */
    private fun diagnosticImageResponse(request: Request, message: String): Response {
        val width = 900
        val height = 500
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        canvas.drawColor(android.graphics.Color.BLACK)

        val paint = android.graphics.Paint().apply {
            color = android.graphics.Color.RED
            textSize = 26f
            isAntiAlias = true
        }

        val words = message.split(" ")
        val lines = mutableListOf<String>()
        var current = StringBuilder()
        for (word in words) {
            val trial = if (current.isEmpty()) word else "$current $word"
            if (paint.measureText(trial) > width - 40) {
                lines.add(current.toString())
                current = StringBuilder(word)
            } else {
                current = StringBuilder(trial)
            }
        }
        if (current.isNotEmpty()) lines.add(current.toString())

        lines.take(13).forEachIndexed { i, line ->
            canvas.drawText(line, 20f, 40f + i * 34f, paint)
        }

        val output = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.JPEG, 92, output)
        bitmap.recycle()

        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(200)
            .message("OK")
            .body(output.toByteArray().toResponseBody("image/jpeg".toMediaType()))
            .build()
    }
}
