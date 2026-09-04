package eu.kanade.tachiyomi.extension.ar.procomic

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
import kotlinx.serialization.json.JsonElement
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.time.Instant

@Source
abstract class ProComic : KeiSource() {

    private val apiUrl = "$baseUrl/api"

    override val supportsLatest = true

    override fun Headers.Builder.configureHeaders() = apply {
        add("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
        add("Accept-Language", "ar,en;q=0.8")
        add("Referer", "$baseUrl/")
    }

    override fun OkHttpClient.Builder.configureClient() = rateLimit(2)

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
        val pageUrls = document.select("script")
            .asSequence()
            .flatMap { APP_IMAGE_REGEX.findAll(it.html()).map { match -> match.value } }
            .distinct()
            .toList()

        return pageUrls.mapIndexed { index, imageUrl ->
            Page(index, imageUrl = imageUrl)
        }
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

    private fun ContentDto.toSManga(url: String = "$slug-$id") = SManga.create().apply {
        this.url = url
        title = this@toSManga.title
        description = metadata?.descriptions?.get("ar") ?: description
        author = metadata?.author
        artist = metadata?.artist
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
        val author: String? = null,
        val artist: String? = null,
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
    }
}
