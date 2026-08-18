/**
 * @file dci_tests.cpp
 * @brief Tests for DeepContentInspector document detection and extraction.
 *
 * PRITRAK Enterprise DLP Agent
 *
 * Fixtures are generated in memory (miniz builds the OOXML ZIP containers;
 * raw bytes for text/PDF/OLE/corrupt/bomb cases) and written to the temp
 * directory, so no binary fixtures are committed to the repository.
 */

#include "DeepContentInspector.h"

#include <windows.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include <miniz.h>

#include "test_main.h"

using namespace Pritrak::DLP;

namespace {

int g_counter = 0;

std::wstring MakeTempPath(const char* tag, const char* ext) {
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    wchar_t name[MAX_PATH];
    swprintf(name, MAX_PATH, L"pritrak_dci_%S_%u_%d.%S",
             tag, GetCurrentProcessId(), ++g_counter, ext);
    return std::wstring(dir) + name;
}

void WriteFile(const std::wstring& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary);
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    f.close();
}

void WriteZip(const std::wstring& path,
              const std::vector<std::pair<std::string, std::string>>& entries,
              int level = MZ_DEFAULT_COMPRESSION) {
    // Convert the (ASCII) temp path to narrow for miniz.
    int n = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string narrow(n > 0 ? n - 1 : 0, '\0');
    if (n > 0) {
        WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, &narrow[0], n, nullptr, nullptr);
    }

    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_file(&zip, narrow.c_str(), 0)) {
        std::printf("FAIL: mz_zip_writer_init_file failed\n");
        return;
    }
    for (const auto& e : entries) {
        mz_zip_writer_add_mem(&zip, e.first.c_str(), e.second.data(), e.second.size(), level);
    }
    mz_zip_writer_finalize_archive(&zip);
    mz_zip_writer_end(&zip);
}

std::string EncodeUtf16Le(const std::string& ascii) {
    std::string out;
    out.reserve(ascii.size() * 2);
    for (char c : ascii) {
        out.push_back(c);
        out.push_back('\0');
    }
    return out;
}

ExtractionResult Inspect(const std::wstring& path) {
    DeepContentInspector inspector;
    return inspector.ExtractDocument(path);
}

// ---------------------------------------------------------------------------
// OOXML fixture content
// ---------------------------------------------------------------------------

const char* kPkgTypesNs =
    "xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"";
const char* kRelNs =
    "xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"";
const char* kWordNs =
    "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"";
const char* kSheetNs =
    "xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"";
const char* kPresNs =
    "xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" "
    "xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"";

std::vector<std::pair<std::string, std::string>> BuildDocxEntries() {
    return {
        {"[Content_Types].xml",
         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
         "<Types " + std::string(kPkgTypesNs) + ">"
         "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
         "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
         "<Override PartName=\"/word/document.xml\" "
         "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
         "</Types>"},
        {"word/document.xml",
         "<w:document " + std::string(kWordNs) + ">"
         "<w:body>"
         "<w:p><w:r><w:t>Hello from body</w:t></w:r></w:p>"
         "<w:tbl><w:tr>"
         "<w:tc><w:p><w:r><w:t>TableCellOne</w:t></w:r></w:p></w:tc>"
         "<w:tc><w:p><w:r><w:t>TableCellTwo</w:t></w:r></w:p></w:tc>"
         "</w:tr></w:tbl>"
         "</w:body></w:document>"},
        {"word/header1.xml",
         "<w:hdr " + std::string(kWordNs) + "><w:p><w:r><w:t>HeaderTitleText</w:t></w:r></w:p></w:hdr>"},
        {"word/footer1.xml",
         "<w:ftr " + std::string(kWordNs) + "><w:p><w:r><w:t>FooterStampText</w:t></w:r></w:p></w:ftr>"},
        {"word/footnotes.xml",
         "<w:footnotes " + std::string(kWordNs) + ">"
         "<w:footnote w:id=\"1\"><w:p><w:r><w:t>FootnoteText</w:t></w:r></w:p></w:footnote>"
         "</w:footnotes>"},
    };
}

std::vector<std::pair<std::string, std::string>> BuildXlsxEntries() {
    return {
        {"[Content_Types].xml",
         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
         "<Types " + std::string(kPkgTypesNs) + ">"
         "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
         "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
         "<Override PartName=\"/xl/workbook.xml\" "
         "ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
         "</Types>"},
        {"xl/_rels/workbook.xml.rels",
         "<Relationships " + std::string(kRelNs) + ">"
         "<Relationship Id=\"rId1\" "
         "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" "
         "Target=\"worksheets/sheet1.xml\"/>"
         "<Relationship Id=\"rId2\" "
         "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" "
         "Target=\"worksheets/sheet2.xml\"/>"
         "</Relationships>"},
        {"xl/sharedStrings.xml",
         "<sst " + std::string(kSheetNs) + ">"
         "<si><t>SharedStringAlpha</t></si>"
         "<si><t>SharedStringBeta</t></si>"
         "</sst>"},
        {"xl/worksheets/sheet1.xml",
         "<worksheet " + std::string(kSheetNs) + "><sheetData>"
         "<row r=\"1\">"
         "<c r=\"A1\" t=\"s\"><v>0</v></c>"
         "<c r=\"B1\" t=\"inlineStr\"><is><t>InlineCellGamma</t></is></c>"
         "<c r=\"C1\"><v>42</v></c>"
         "<c r=\"D1\" t=\"b\"><v>1</v></c>"
         "</row>"
         "<row r=\"2\"><c r=\"A2\" t=\"s\"><v>1</v></c></row>"
         "</sheetData></worksheet>"},
        {"xl/worksheets/sheet2.xml",
         "<worksheet " + std::string(kSheetNs) + "><sheetData>"
         "<row r=\"1\">"
         "<c r=\"A1\"><v>9.5</v></c>"
         "<c r=\"B1\" t=\"str\"><v>FormulaResult</v></c>"
         "</row>"
         "</sheetData></worksheet>"},
    };
}

std::vector<std::pair<std::string, std::string>> BuildPptxEntries() {
    return {
        {"[Content_Types].xml",
         "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
         "<Types " + std::string(kPkgTypesNs) + ">"
         "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
         "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
         "<Override PartName=\"/ppt/presentation.xml\" "
         "ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/>"
         "</Types>"},
        {"ppt/_rels/presentation.xml.rels",
         "<Relationships " + std::string(kRelNs) + ">"
         "<Relationship Id=\"rId1\" "
         "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" "
         "Target=\"slides/slide1.xml\"/>"
         "<Relationship Id=\"rId2\" "
         "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" "
         "Target=\"slides/slide2.xml\"/>"
         "</Relationships>"},
        {"ppt/slides/slide1.xml",
         "<p:sld " + std::string(kPresNs) + ">"
         "<p:cSld><p:spTree><p:sp><p:txBody>"
         "<a:p><a:r><a:t>SlideOneText</a:t></a:r></a:p>"
         "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"},
        {"ppt/slides/slide2.xml",
         "<p:sld " + std::string(kPresNs) + ">"
         "<p:cSld><p:spTree><p:sp><p:txBody>"
         "<a:p><a:r><a:t>SlideTwoText</a:t></a:r></a:p>"
         "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"},
    };
}

} // namespace

// ---------------------------------------------------------------------------
// TEXT FIXTURES
// ---------------------------------------------------------------------------

TEST(text_ascii) {
    std::wstring path = MakeTempPath("ascii", "txt");
    WriteFile(path, "Plain ASCII text line one.\nSecond line 12345.\n");
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("text"));
    CHECK_EQ(res.errorCategory, std::string(""));
    CHECK_CONTAINS(res.extractedText, "Plain ASCII text line one.");
    std::filesystem::remove(path);
}

TEST(text_utf8_no_bom) {
    std::wstring path = MakeTempPath("utf8", "txt");
    WriteFile(path, std::string("caf\xC3\xA9 \xE2\x82\xAC 100"));
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("text"));
    CHECK_CONTAINS(res.extractedText, std::string("caf\xC3\xA9"));
    std::filesystem::remove(path);
}

TEST(text_utf8_bom) {
    std::wstring path = MakeTempPath("utf8bom", "txt");
    WriteFile(path, std::string("\xEF\xBB\xBF") + "BOM prefixed text");
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("text"));
    CHECK_CONTAINS(res.extractedText, "BOM prefixed text");
    CHECK(res.extractedText.empty() ||
          static_cast<unsigned char>(res.extractedText[0]) != 0xEF);
    std::filesystem::remove(path);
}

TEST(text_utf16le) {
    std::wstring path = MakeTempPath("utf16le", "txt");
    WriteFile(path, std::string("\xFF\xFE") + EncodeUtf16Le("UTF16 text here"));
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("text"));
    CHECK_CONTAINS(res.extractedText, "UTF16 text here");
    std::filesystem::remove(path);
}

TEST(text_malformed_encoding_graceful) {
    std::wstring path = MakeTempPath("malformed", "txt");
    WriteFile(path, std::string("ascii lead \x80\x80\x80\xF0\x28\x8C\x28 tail"));
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("text"));
    // Must be handled gracefully (no crash): either a warning is produced or
    // the text is still converted to valid UTF-8 for scanning.
    bool warned = false;
    for (const auto& w : res.warnings) {
        if (w == "malformed_encoding") {
            warned = true;
        }
    }
    CHECK(warned);
    std::filesystem::remove(path);
}

TEST(text_oversized_rejected) {
    std::wstring path = MakeTempPath("oversized", "txt");
    WriteFile(path, std::string(DciLimits::kMaxInputBytes + 1, 'a'));
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kTooLarge));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(text_binary_rejected) {
    std::wstring path = MakeTempPath("binary", "bin");
    std::string bin;
    bin.resize(2048, 0x00);
    bin[0] = 'M';  // not a known signature; NUL bytes dominate
    WriteFile(path, bin);
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kBinary));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

// ---------------------------------------------------------------------------
// PDF / OLE
// ---------------------------------------------------------------------------

TEST(pdf_detected_not_supported) {
    std::wstring path = MakeTempPath("pdf", "pdf");
    WriteFile(path, std::string("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n1 0 obj\n"));
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("pdf"));
    CHECK_EQ(res.errorCategory, std::string(DciError::kUnsupported));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(ole_legacy_doc_rejected) {
    std::wstring path = MakeTempPath("legacy", "doc");
    std::string ole;
    ole.append("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8);
    ole.append(512, '\0');
    WriteFile(path, ole);
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("ole"));
    CHECK_EQ(res.errorCategory, std::string(DciError::kUnsupported));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(ole_encrypted_package_detected) {
    std::wstring path = MakeTempPath("encrypted", "docx");
    std::string ole;
    ole.append("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8);
    ole += "EncryptionInfo\x00\x00EncryptedPackage";
    ole.append(256, '\0');
    WriteFile(path, ole);
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("ole"));
    CHECK_EQ(res.errorCategory, std::string(DciError::kEncrypted));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

// ---------------------------------------------------------------------------
// OOXML FIXTURES
// ---------------------------------------------------------------------------

TEST(docx_body_table_header_footer) {
    std::wstring path = MakeTempPath("docx", "docx");
    WriteZip(path, BuildDocxEntries());
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("docx"));
    CHECK_EQ(res.errorCategory, std::string(""));
    CHECK_CONTAINS(res.extractedText, "Hello from body");
    CHECK_CONTAINS(res.extractedText, "TableCellOne");
    CHECK_CONTAINS(res.extractedText, "TableCellTwo");
    CHECK_CONTAINS(res.extractedText, "HeaderTitleText");
    CHECK_CONTAINS(res.extractedText, "FooterStampText");
    CHECK_CONTAINS(res.extractedText, "FootnoteText");
    std::filesystem::remove(path);
}

TEST(docx_detected_by_content_not_extension) {
    // Renamed to .txt - detection must rely on the ZIP signature and
    // [Content_Types].xml, not the file extension.
    std::wstring path = MakeTempPath("renamed_docx", "txt");
    WriteZip(path, BuildDocxEntries());
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("docx"));
    CHECK_CONTAINS(res.extractedText, "Hello from body");
    std::filesystem::remove(path);
}

TEST(xlsx_shared_inline_numeric_bool_multi_sheet) {
    std::wstring path = MakeTempPath("xlsx", "xlsx");
    WriteZip(path, BuildXlsxEntries());
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("xlsx"));
    CHECK_EQ(res.errorCategory, std::string(""));
    CHECK_CONTAINS(res.extractedText, "SharedStringAlpha");
    CHECK_CONTAINS(res.extractedText, "SharedStringBeta");
    CHECK_CONTAINS(res.extractedText, "InlineCellGamma");
    CHECK_CONTAINS(res.extractedText, "42");
    CHECK_CONTAINS(res.extractedText, "TRUE");
    CHECK_CONTAINS(res.extractedText, "FormulaResult");
    CHECK_CONTAINS(res.extractedText, "9.5");
    // Cell separators must preserve cell boundaries.
    CHECK_CONTAINS(res.extractedText, "|");
    std::filesystem::remove(path);
}

TEST(pptx_multiple_slides) {
    std::wstring path = MakeTempPath("pptx", "pptx");
    WriteZip(path, BuildPptxEntries());
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.fileType, std::string("pptx"));
    CHECK_EQ(res.errorCategory, std::string(""));
    CHECK_CONTAINS(res.extractedText, "SlideOneText");
    CHECK_CONTAINS(res.extractedText, "SlideTwoText");
    size_t first = res.extractedText.find("SlideOneText");
    size_t second = res.extractedText.find("SlideTwoText");
    CHECK(first != std::string::npos && second != std::string::npos && first < second);
    std::filesystem::remove(path);
}

TEST(non_ooxml_zip_rejected) {
    std::wstring path = MakeTempPath("plainzip", "zip");
    WriteZip(path, {{"readme.txt", "just a plain zip archive"}});
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kUnsupported));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(corrupt_zip_rejected) {
    std::wstring path = MakeTempPath("corrupt", "zip");
    WriteFile(path, std::string("PK\x03\x04garbage-not-a-real-zip"));
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kCorrupt));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(zip_bomb_rejected) {
    std::wstring path = MakeTempPath("bomb", "zip");
    const std::string zeros(100ULL * 1024 * 1024, '\0');
    WriteZip(path, {{"data.bin", zeros}}, MZ_BEST_COMPRESSION);
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kZipBomb));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(too_many_entries_rejected) {
    std::wstring path = MakeTempPath("many", "zip");
    std::vector<std::pair<std::string, std::string>> entries;
    entries.reserve(DciLimits::kMaxArchiveEntries + 1);
    for (uint32_t i = 0; i <= DciLimits::kMaxArchiveEntries; ++i) {
        entries.push_back({"f" + std::to_string(i), "x"});
    }
    WriteZip(path, entries, MZ_NO_COMPRESSION);
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kTooManyEntries));
    CHECK(res.extractedText.empty());
    std::filesystem::remove(path);
}

TEST(traversal_entry_rejected) {
    std::wstring path = MakeTempPath("traversal", "docx");
    auto entries = BuildDocxEntries();
    entries.push_back({"../evil.xml", "<x>should not be read</x>"});
    WriteZip(path, entries);
    ExtractionResult res = Inspect(path);
    // The malicious entry is skipped; the document still extracts.
    CHECK_EQ(res.errorCategory, std::string(""));
    CHECK_CONTAINS(res.extractedText, "Hello from body");
    bool rejected = false;
    for (const auto& w : res.warnings) {
        if (w == "rejected_malformed_entry") {
            rejected = true;
        }
    }
    CHECK(rejected);
    std::filesystem::remove(path);
}

TEST(nested_archive_not_recursed) {
    // An OOXML container may embed other archives (e.g. an embedded xlsx).
    // Nesting depth is zero: the embedded archive is never parsed.
    std::wstring path = MakeTempPath("nested", "docx");
    auto entries = BuildDocxEntries();
    std::string embeddedZip;
    {
        // Build a tiny zip in memory that, if (incorrectly) recursed into,
        // would leak "EmbeddedSecretText".
        mz_zip_archive w;
        memset(&w, 0, sizeof(w));
        mz_zip_writer_init_heap(&w, 0, 1024);
        const std::string inner = "EmbeddedSecretText";
        mz_zip_writer_add_mem(&w, "inner.txt", inner.data(), inner.size(), MZ_NO_COMPRESSION);
        void* buf = nullptr;
        size_t size = 0;
        if (mz_zip_writer_finalize_heap_archive(&w, &buf, &size)) {
            embeddedZip.assign(static_cast<const char*>(buf), size);
        }
        mz_zip_writer_end(&w);
    }
    entries.push_back({"word/embeddings/oleObject1.xlsx", embeddedZip});
    WriteZip(path, entries);
    ExtractionResult res = Inspect(path);
    CHECK_EQ(res.errorCategory, std::string(""));
    CHECK_CONTAINS(res.extractedText, "Hello from body");
    CHECK_NOT_CONTAINS(res.extractedText, "EmbeddedSecretText");
    std::filesystem::remove(path);
}

TEST(deadline_zero_times_out) {
    DeepContentInspector inspector;
    inspector.SetDeadline(std::chrono::milliseconds(0));
    std::wstring path = MakeTempPath("deadline", "docx");
    WriteZip(path, BuildDocxEntries());
    ExtractionResult res = inspector.ExtractDocument(path);
    CHECK_EQ(res.errorCategory, std::string(DciError::kTimeout));
    std::filesystem::remove(path);
}

// ---------------------------------------------------------------------------
// PII INSIDE OOXML (integration)
// ---------------------------------------------------------------------------

TEST(pii_detected_inside_docx) {
    std::wstring path = MakeTempPath("docxpii", "docx");
    auto entries = BuildDocxEntries();
    // Body contains a valid-Luhn card and an SSN.
    std::string doc = entries[1].second;
    std::string pii = "<w:p><w:r><w:t>Card 4111 1111 1111 1111 and SSN 123-45-6789</w:t></w:r></w:p>";
    doc.insert(doc.rfind("</w:body>"), pii);
    entries[1].second = doc;
    WriteZip(path, entries);

    DeepContentInspector inspector;
    ExtractionResult res = inspector.ExtractDocument(path);
    CHECK_EQ(res.fileType, std::string("docx"));
    auto hits = DeepContentInspector::ScanTextForPII(res.extractedText);
    bool foundCard = false;
    bool foundSsn = false;
    for (const auto& h : hits) {
        if (h.find("4111") != std::string::npos) {
            foundCard = true;
        }
        if (h == "123-45-6789") {
            foundSsn = true;
        }
    }
    CHECK(foundCard);
    CHECK(foundSsn);
    std::filesystem::remove(path);
}