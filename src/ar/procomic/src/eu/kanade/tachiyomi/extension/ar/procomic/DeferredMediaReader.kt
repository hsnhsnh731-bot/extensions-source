/**
 * DeferredMediaReader.kt
 *
 * يطبق آلية جلب وفك تشفير صفحات الفصول المؤجلة (deferred media) لموقع procomic.pro.
 *
 * الطريقة كاملة (مستخرجة من ملف page-70d29726605443ff.js عبر PCAPdroid + تحليل الجافاسكربت):
 *
 * 1. الصفحة الأولية تحتوي على deferredMedia.token (JWT موقّع، ليس مشفّرًا) و splitIndex.
 * 2. GET /chapter-deferred-media/{chapterId}?token={token}&split={splitIndex}
 *    يرجع { data: { images: [...], maps: [...] } }
 * 3. كل عنصر بـ maps[] له "token" (base64url JSON) يحتوي v, m, cid, iv, tag, data
 * 4. حسب "m":
 *    - "browser"          -> المفتاح = SHA-256("prochan-browser-map:" + STATIC_SALT + ":" + chapterId)
 *    - "browser_session"  -> المفتاح يُجلب من GET /chapter-map-session-key/{chapterId}?legacy=1 (مع الكوكيز)
 * 5. فك تشفير AES-GCM(key, iv, data+tag) -> JSON يحتوي { dim:[w,h], mode:"grid_2x3", pieces:[...], order:[...] }
 * 6. تجميع القطع (pieces) بترتيبها الصحيح (order) على Bitmap واحد حسب mode.
 * 7. قطع الصور (pieces) قد تكون روابط cdn2 كاملة أو مسارات نسبية؛ الروابط المحمية على
 *    cdn2.procomic.pro تحتاج لآلية التوقيع القديمة قبل التنزيل:
 *      POST /api/cdn-image/sign  { "url": cdn2Url }  -> { token, expires }
 *      GET  /api/cdn-image?expires=..&token=..&url=..  -> بايتات الصورة الفعلية
 *
 * ملاحظة مهمة: القيم التالية غير مؤكدة 100% وتحتاج اختبار فعلي على فصل حقيقي:
 *   - الصيغة الدقيقة لـ mode ("grid_{cols}x{rows}", "vertical_{n}", "horizontal_{n}")
 *   - هل pieces تصل دائمًا كروابط كاملة أو نسبية
 *
 * يفترض هذا الملف وجود:
 *   - `client: OkHttpClient` (موجود أصلًا بكل مصادر Mihon كخاصية بـ HttpSource)
 *   - `json: Json` (kotlinx.serialization، موجود أصلًا)
 *   - دالة موجودة مسبقًا لتوقيع روابط cdn2: signCdnImageUrl(rawCdn2Url: String): String
 *     (إذا غير موجودة، أضفتها بالأسفل كمرجع)
 */

package eu.kanade.tachiyomi.extension.ar.procomic

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.util.Base64
import keiyoushi.utils.jsonInstance
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ============================================================
// ثوابت مستخرجة من الجافاسكربت الأصلي (page-70d29726605443ff.js)
// ============================================================

private const val STATIC_SALT =
    "2e6f9a1c4d8b7e3f0a5c9d2b6e1f4a8c7d3b0e6a9f2c5d8b1e4a7c0d3f6b9e2"

private const val GCM_TAG_LENGTH_BYTES = 16
private const val GCM_TAG_LENGTH_BITS = GCM_TAG_LENGTH_BYTES * 8

// ============================================================
// نماذج JSON (data classes)
// ============================================================

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
    val cid: JsonElement, // قد تصل كنص أو رقم
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

// ============================================================
// دوال base64url
// ============================================================

private fun decodeBase64Url(input: String): ByteArray {
    val normalized = input.replace('-', '+').replace('_', '/')
    val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
    return Base64.decode(padded, Base64.DEFAULT)
}

// ============================================================
// الخطوة 1: جلب الوسائط المؤجلة
// ============================================================

/**
 * GET /chapter-deferred-media/{chapterId}?token={token}&split={splitIndex}
 */
fun fetchDeferredMedia(
    client: OkHttpClient,
    json: Json,
    baseUrl: String,
    chapterId: Long,
    deferredToken: String,
    splitIndex: Int,
): DeferredMediaData {
    val url = "$baseUrl/chapter-deferred-media/$chapterId" +
        "?token=${java.net.URLEncoder.encode(deferredToken, "UTF-8")}" +
        "&split=$splitIndex"

    val request = Request.Builder()
        .url(url)
        .header("Accept", "application/json")
        .build()

    client.newCall(request).execute().use { response ->
        val body = response.body?.string().orEmpty()
        val envelope = json.decodeFromString(DeferredMediaEnvelope.serializer(), body)
        return envelope.data ?: DeferredMediaData()
    }
}

// ============================================================
// الخطوة 2: فك ترميز الـ token الداخلي لكل map entry
// ============================================================

fun parseReconstructionEnvelope(json: Json, mapEntry: MapEntry): ReconstructionEnvelope {
    val decoded = decodeBase64Url(mapEntry.token)
    val text = String(decoded, Charsets.UTF_8)
    return json.decodeFromString(ReconstructionEnvelope.serializer(), text)
}

// ============================================================
// الخطوة 3: اشتقاق أو جلب مفتاح AES-GCM
// ============================================================

/** الطريقة "browser": مفتاح مشتق محليًا، بدون أي طلب شبكة */
fun deriveBrowserKey(chapterId: Long): SecretKeySpec {
    val material = "prochan-browser-map:$STATIC_SALT:$chapterId"
    val digest = MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.UTF_8))
    return SecretKeySpec(digest, "AES")
}

/**
 * الطريقة "browser_session": يجلب المفتاح الخام (base64url) من الخادم.
 * GET /chapter-map-session-key/{chapterId}?legacy=1
 * لازم يُرسل مع كوكيز الجلسة (client الخاص بـ Mihon يرسلها تلقائيًا عبر CookieJar).
 */
fun fetchSessionKey(
    client: OkHttpClient,
    json: Json,
    baseUrl: String,
    chapterId: Long,
): SecretKeySpec {
    val url = "$baseUrl/chapter-map-session-key/$chapterId?legacy=1"

    val request = Request.Builder()
        .url(url)
        .header("Accept", "application/json")
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
        return SecretKeySpec(keyBytes, "AES")
    }
}

// ============================================================
// الخطوة 4: فك تشفير AES-GCM
// ============================================================

fun decryptReconstructionMap(
    json: Json,
    envelope: ReconstructionEnvelope,
    key: SecretKeySpec,
): ReconstructionMap {
    val iv = decodeBase64Url(envelope.iv)
    val tag = decodeBase64Url(envelope.tag)
    val cipherTextOnly = decodeBase64Url(envelope.data)

    // الملف الأصلي يلصق الـ tag بآخر الـ ciphertext قبل تمريره لـ WebCrypto.
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
        "browser_session" -> fetchSessionKey(client, json, baseUrl, chapterId)
        else -> throw Exception("Unsupported reconstruction map method: ${envelope.m}")
    }

    return decryptReconstructionMap(json, envelope, key)
}

// ============================================================
// الخطوة 5: حساب مستطيلات القطع (لو "rects" غير موجودة بالخريطة)
// ============================================================

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
        for (i in 0 until cols) { colOffsets[i] = acc; acc += colWidths[i] }

        val rowOffsets = IntArray(rows)
        acc = 0
        for (i in 0 until rows) { rowOffsets[i] = acc; acc += rowHeights[i] }

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

    // vertical أو horizontal: تقسيم على محور واحد فقط
    val segments = if (kind == "vertical") param.toIntOrNull()?.coerceAtLeast(1) ?: pieceCount else pieceCount
    val total = if (kind == "vertical") width else height
    val baseSize = total / segments
    val extra = total - baseSize * segments
    val sizes = IntArray(segments) { i -> (baseSize + if (i < extra) 1 else 0).coerceAtLeast(1) }
    val offsets = IntArray(segments)
    var acc2 = 0
    for (i in 0 until segments) { offsets[i] = acc2; acc2 += sizes[i] }

    return List(pieceCount) { index ->
        if (kind == "vertical") {
            PieceRect(left = offsets.getOrElse(index) { 0 }, top = 0, width = sizes.getOrElse(index) { width }, height = height)
        } else {
            PieceRect(left = 0, top = offsets.getOrElse(index) { 0 }, width = width, height = sizes.getOrElse(index) { height })
        }
    }
}

// ============================================================
// الخطوة 6: تنزيل قطعة واحدة (مع التوقيع لو محمية على cdn2)
// ============================================================

private const val CDN2_HOST_MARKER = "cdn2.procomic.pro"

/**
 * يوقّع رابط cdn2 عبر الآلية المكتشفة بالجلسة الثالثة:
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

    val payload = """{"url":"$rawUrl"}"""
    val signRequest = Request.Builder()
        .url("$baseUrl/api/cdn-image/sign")
        .post(payload.toRequestBody("application/json".toMediaType()))
        .build()

    client.newCall(signRequest).execute().use { response ->
        val body = response.body?.string().orEmpty()
        val jsonObj = json.parseToJsonElement(body).let { it as? kotlinx.serialization.json.JsonObject }
            ?: throw Exception("Invalid sign response")
        val token = jsonObj["token"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
            ?: throw Exception("Sign response missing token")
        val expires = jsonObj["expires"]?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
            ?: throw Exception("Sign response missing expires")

        val encodedUrl = java.net.URLEncoder.encode(rawUrl, "UTF-8")
        return "$baseUrl/api/cdn-image?expires=$expires&token=$token&url=$encodedUrl"
    }
}

/** يحل رابط قطعة نسبي إلى رابط مطلق كامل، إذا لزم الأمر */
fun resolvePieceUrl(baseUrl: String, rawPiece: String, cdnPath: String?): String {
    return when {
        rawPiece.startsWith("http://") || rawPiece.startsWith("https://") -> rawPiece
        rawPiece.startsWith("/") -> baseUrl.trimEnd('/') + rawPiece
        !cdnPath.isNullOrBlank() -> "https://$cdnPath.procomic.pro/$rawPiece".let {
            // fallback بسيط: لو cdnPath هو "cdn2" فقط
            if (cdnPath.contains(".")) "https://$cdnPath/$rawPiece" else it
        }
        else -> rawPiece
    }
}

private fun downloadPieceBitmap(client: OkHttpClient, url: String): Bitmap {
    val request = Request.Builder().url(url).build()
    client.newCall(request).execute().use { response ->
        if (!response.isSuccessful) throw Exception("Failed to download piece: HTTP ${response.code} ($url)")
        val bytes = response.body?.bytes() ?: throw Exception("Empty piece body ($url)")
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            ?: throw Exception("Failed to decode piece bitmap ($url)")
    }
}

// ============================================================
// الخطوة 7: تجميع القطع على Bitmap واحد
// ============================================================

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

    // map.order يحدد أي قطعة (index بـ pieces) تروح لأي موقع بالترتيب
    map.order.forEachIndexed { positionIndex, pieceIndex ->
        val rawPieceUrl = map.pieces.getOrNull(pieceIndex)
            ?: throw Exception("Missing piece at index $pieceIndex")

        val resolvedUrl = resolvePieceUrl(baseUrl, rawPieceUrl, cdnPath)
        val finalUrl = buildSignedImageUrlSafely(client, baseUrl, resolvedUrl)

        val pieceBitmap = downloadPieceBitmap(client, finalUrl)
        val rect = rects.getOrNull(positionIndex)
            ?: throw Exception("Missing rect for position $positionIndex")

        val destRect = android.graphics.Rect(rect.left, rect.top, rect.left + rect.width, rect.top + rect.height)
        canvas.drawBitmap(pieceBitmap, null, destRect, null)
        pieceBitmap.recycle()
    }

    val output = ByteArrayOutputStream()
    finalBitmap.compress(Bitmap.CompressFormat.JPEG, 92, output)
    finalBitmap.recycle()
    return output.toByteArray()
}

/** يوقّع الرابط فقط لو محتاج توقيع، بدون تفجير الاستثناء لو فشل التوقيع (fallback للرابط الأصلي) */
private fun buildSignedImageUrlSafely(client: OkHttpClient, baseUrl: String, url: String): String {
    return try {
        val json = Json { ignoreUnknownKeys = true }
        buildSignedImageUrl(client, json, baseUrl, url)
    } catch (e: Exception) {
        url
    }
}

// ============================================================
// اكتشاف مهم (جلسة تحليل HttpSource.kt الرسمي من مستودع Mihon):
//
// دالة getImage(page) بـ HttpSource نهائية (final) ولا يمكن استبدالها.
// هي تستدعي imageRequest(page) لبناء طلب HTTP واحد فقط، ثم تنفذه عبر client.
//
// الحل الصحيح إذن: لسنا نستبدل fetchImage، بل نضيف Interceptor مخصص
// على مستوى OkHttpClient (عبر configureClient بـ KeiSource) يعترض الطلبات
// الموجّهة لمضيف داخلي وهمي (procomic-map.internal)، ويبني Response يدويًا
// من الصورة المجمّعة، بدل ما يرسل طلب فعلي للإنترنت لذلك الرابط.
// ============================================================

// ============================================================
// ذاكرة مؤقتة لتخزين maps[] الخاصة بكل فصل، بحيث يقدر الـ Interceptor
// يوصل لها لاحقًا وقت تحميل كل صورة (الفصل قد يُحمَّل مرة، وصفحاته تُطلب لاحقًا).
// ============================================================

object ProComicMapCache {
    private val cache = ConcurrentHashMap<Long, List<MapEntry>>()

    fun store(chapterId: Long, maps: List<MapEntry>) {
        cache[chapterId] = maps
    }

    fun get(chapterId: Long, mapIndex: Int): MapEntry? {
        return cache[chapterId]?.getOrNull(mapIndex)
    }
}

// ============================================================
// الـ Interceptor: يعترض الطلبات لروابط procomic-map.internal فقط،
// ويترك أي طلب آخر يمر بشكل طبيعي.
// ============================================================

const val PROCOMIC_MAP_HOST = "procomic-map.internal"

class ProComicMapInterceptor(private val source: ProComic) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val url = request.url

        if (url.host != PROCOMIC_MAP_HOST) {
            return chain.proceed(request)
        }

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
                json = jsonInstance,
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
            errorResponse(request, 500, e.message ?: "Failed to assemble protected page")
        }
    }

    private fun errorResponse(request: Request, code: Int, message: String): Response {
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message(message)
            .body(ByteArray(0).toResponseBody(null))
            .build()
    }
}

// ============================================================
// التعديلات المطلوبة بالضبط داخل ProComic.kt (الملف الحالي)
// ============================================================

/*
1) عدّل configureClient لإضافة الـ Interceptor فوق ما هو موجود أصلًا:

    override fun OkHttpClient.Builder.configureClient() =
        rateLimit(2).addInterceptor(ProComicMapInterceptor(this@ProComic))

2) استبدل دالة getPageList() الحالية بالكامل بهذا:

    override suspend fun getPageList(chapter: SChapter): List<Page> {
        val document = client.get("$baseUrl${chapter.url}".toHttpUrl()).asJsoup()
        val payload = document.select("script").joinToString(separator = "") { it.html() }

        val pageUrls = APP_IMAGE_REGEX.findAll(payload)
            .map { it.value }
            .distinct()
            .toList()

        val pages = pageUrls.mapIndexed { index, imageUrl ->
            Page(index, imageUrl = imageUrl)
        }.toMutableList()

        val chapterId = chapter.url.substringAfterLast("-").toLongOrNull()
        val deferredBlock = DEFERRED_MEDIA_REGEX.find(payload)?.groupValues?.get(1)
        val token = deferredBlock?.let { TOKEN_REGEX.find(it)?.groupValues?.get(1) }

        if (chapterId != null && token != null) {
            val splitIndex = deferredBlock
                ?.let { SPLIT_INDEX_REGEX.find(it)?.groupValues?.get(1)?.toIntOrNull() }
                ?: pages.size

            try {
                val deferredData = fetchDeferredMedia(
                    client = client,
                    json = jsonInstance,
                    baseUrl = baseUrl,
                    chapterId = chapterId,
                    deferredToken = token,
                    splitIndex = splitIndex,
                )

                // صور إضافية مباشرة (لو رجعت غير مشفّرة)
                deferredData.images.forEach { imageUrl ->
                    pages.add(Page(pages.size, imageUrl = imageUrl))
                }

                // خرائط محمية تحتاج فك تشفير وتجميع قطع؛ نخزّنها ونضيف
                // صفحات وهمية تشير للـ Interceptor بدل رابط صورة مباشر.
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

3) أضف هذي الثوابت الثلاثة جوا companion object الموجود أصلًا (بجانب PAGE_SIZE، SUPPORTED_TYPES، APP_IMAGE_REGEX):

    val DEFERRED_MEDIA_REGEX = Regex(""""deferredMedia":\{([^{}]*)\}""")
    val TOKEN_REGEX = Regex(""""token":"([^"]+)"""")
    val SPLIT_INDEX_REGEX = Regex(""""splitIndex":(\d+)""")

4) الملف الحالي DeferredMediaReader.kt يُحفظ كملف منفصل بنفس مجلد ProComic.kt
   (نفس الـ package بالأعلى)، ولا يحتاج أي تعديل إضافي غير المذكور أعلاه.
*/
