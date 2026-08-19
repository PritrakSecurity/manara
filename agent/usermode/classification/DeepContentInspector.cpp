/**
 * @file DeepContentInspector.cpp
 * @brief Phase 2 DSPM Deep Content Inspection (DCI) - implementation
 *
 * PRITRAK Enterprise DLP Agent
 *
 * Copyright (C) 2026 Pritrak Security
 */

#include "DeepContentInspector.h"

#include "../../common/utils/logging.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <miniz.h>
#include <pugixml.hpp>
#include <re2/re2.h>

// Note: never log extracted text, PII candidates, document contents or secrets.
// Diagnostics use fixed, non-sensitive strings only.

namespace Pritrak {
namespace DLP {

namespace {

namespace DciLimits_ = DciLimits;

// ============================================================================
// DEADLINE / CANCELLATION CONTEXT
// ============================================================================

struct DciContext {
    std::chrono::steady_clock::time_point start;
    std::chrono::milliseconds deadline;
    const std::atomic<bool>* cancelled;

    bool TimeExpired() const {
        if (cancelled && cancelled->load(std::memory_order_relaxed)) {
            return true;
        }
        if (deadline.count() <= 0) {
            return true;
        }
        return std::chrono::steady_clock::now() - start >= deadline;
    }
};

// ============================================================================
// BOUNDED READ
// ============================================================================

bool ReadFileBounded(const std::wstring& path, size_t maxBytes, std::string& out, std::string& err) {
    std::error_code ec;
    uintmax_t fileSize = std::filesystem::file_size(path, ec);
    if (ec) {
        err = DciError::kReadFailed;
        return false;
    }
    if (fileSize > maxBytes) {
        err = DciError::kTooLarge;
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        err = DciError::kReadFailed;
        return false;
    }

    out.resize(static_cast<size_t>(fileSize));
    if (fileSize > 0) {
        file.read(&out[0], static_cast<std::streamsize>(fileSize));
        if (static_cast<uintmax_t>(file.gcount()) != fileSize) {
            err = DciError::kCorrupt;
            return false;
        }
    }
    return true;
}

// ============================================================================
// ENCODING HELPERS
// ============================================================================

bool IsValidUtf8(const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t c = data[i];
        if (c < 0x80) {
            ++i;
            continue;
        }
        size_t extra;
        uint32_t cp;
        if ((c & 0xE0) == 0xC0) {
            extra = 1;
            cp = static_cast<uint32_t>(c & 0x1F);
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            cp = static_cast<uint32_t>(c & 0x0F);
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            cp = static_cast<uint32_t>(c & 0x07);
        } else {
            return false;
        }
        for (size_t j = 1; j <= extra; ++j) {
            if (i + j >= len) {
                return false;
            }
            uint8_t cc = data[i + j];
            if ((cc & 0xC0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | static_cast<uint32_t>(cc & 0x3F);
        }
        if ((extra == 1 && cp < 0x80) ||
            (extra == 2 && cp < 0x800) ||
            (extra == 3 && cp < 0x10000)) {
            return false; // overlong
        }
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += extra + 1;
    }
    return true;
}

std::string Utf16ToUtf8(const uint8_t* data, size_t len, bool littleEndian, size_t cap, bool* truncated) {
    std::string out;
    out.reserve(std::min(len / 2 + 16, cap));
    auto read16 = [&](size_t off) -> uint16_t {
        if (littleEndian) {
            return static_cast<uint16_t>(data[off] | (static_cast<uint16_t>(data[off + 1]) << 8));
        }
        return static_cast<uint16_t>((static_cast<uint16_t>(data[off]) << 8) | data[off + 1]);
    };
    auto appendCp = [&](uint32_t cp) {
        if (out.size() >= cap) {
            *truncated = true;
            return;
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    };

    for (size_t i = 0; i + 1 < len; i += 2) {
        if (*truncated) {
            break;
        }
        uint16_t u = read16(i);
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (i + 3 < len) {
                uint16_t lo = read16(i + 2);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    uint32_t cp = 0x10000 + ((static_cast<uint32_t>(u - 0xD800)) << 10) + (lo - 0xDC00);
                    appendCp(cp);
                    i += 2;
                    continue;
                }
            }
            appendCp(0xFFFD); // lone high surrogate
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            appendCp(0xFFFD); // lone low surrogate
        } else {
            appendCp(u);
        }
    }
    return out;
}

bool LooksLikeBinary(const uint8_t* data, size_t len) {
    const size_t n = std::min(len, static_cast<size_t>(1024));
    size_t control = 0;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = data[i];
        if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v') || c == 0x7F) {
            ++control;
        }
    }
    // Reject as binary when more than 10% of the sampled bytes are controls.
    return n > 0 && (control * 10 > n);
}

std::string Latin1ToUtf8(const uint8_t* data, size_t len, size_t cap, bool* truncated) {
    std::string out;
    out.reserve(std::min(len * 2, cap));
    for (size_t i = 0; i < len && !(*truncated); ++i) {
        uint8_t c = data[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
        if (out.size() >= cap) {
            *truncated = true;
        }
    }
    return out;
}

ExtractionResult ExtractPlainText(const std::string& raw, const DciContext& ctx) {
    (void)ctx;
    ExtractionResult res;
    res.fileType = "text";

    const uint8_t* data = reinterpret_cast<const uint8_t*>(raw.data());
    const size_t len = raw.size();

    std::string out;
    bool truncated = false;
    bool decoded = false;

    if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        // UTF-8 BOM: strip and validate the remainder.
        const uint8_t* body = data + 3;
        const size_t bodyLen = len - 3;
        if (LooksLikeBinary(body, bodyLen)) {
            res.errorCategory = DciError::kBinary;
            res.warnings.push_back("binary_content");
            return res;
        }
        if (!IsValidUtf8(body, bodyLen)) {
            res.warnings.push_back("malformed_encoding");
            out = Latin1ToUtf8(body, bodyLen, DciLimits_::kMaxExtractedTextBytes, &truncated);
        } else {
            out.assign(reinterpret_cast<const char*>(body), std::min(bodyLen, DciLimits_::kMaxExtractedTextBytes));
            truncated = bodyLen > DciLimits_::kMaxExtractedTextBytes;
        }
        decoded = true;
    } else if (len >= 4 && data[0] == 0xFF && data[1] == 0xFE && data[2] == 0x00 && data[3] == 0x00) {
        res.errorCategory = DciError::kUnsupported;
        res.warnings.push_back("utf32_unsupported");
        return res;
    } else if (len >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        out = Utf16ToUtf8(data + 2, len - 2, true, DciLimits_::kMaxExtractedTextBytes, &truncated);
        decoded = true;
    } else if (len >= 2 && data[0] == 0xFE && data[1] == 0xFF) {
        out = Utf16ToUtf8(data + 2, len - 2, false, DciLimits_::kMaxExtractedTextBytes, &truncated);
        decoded = true;
    }

    if (!decoded) {
        if (LooksLikeBinary(data, len)) {
            res.errorCategory = DciError::kBinary;
            res.warnings.push_back("binary_content");
            return res;
        }
        if (IsValidUtf8(data, len)) {
            out.assign(raw.data(), std::min(len, DciLimits_::kMaxExtractedTextBytes));
            truncated = len > DciLimits_::kMaxExtractedTextBytes;
        } else {
            // Not valid UTF-8 and not binary: deterministic Latin-1 -> UTF-8
            // mapping so ASCII PII patterns remain discoverable.
            res.warnings.push_back("malformed_encoding");
            out = Latin1ToUtf8(data, len, DciLimits_::kMaxExtractedTextBytes, &truncated);
        }
    }

    res.extractedText = out;
    res.truncationStatus = truncated;
    return res;
}

// ============================================================================
// ZIP / OOXML HELPERS
// ============================================================================

bool ValidateEntryName(const std::string& name) {
    if (name.empty()) {
        return false;
    }
    if (name[0] == '/' || name[0] == '\\') {
        return false;
    }
    if (name.find("..") != std::string::npos) {
        return false;
    }
    if (name.find('\\') != std::string::npos) {
        return false;
    }
    if (name.find(':') != std::string::npos) {
        return false; // drive letters / alternate data streams
    }
    if (name.back() == '/') {
        return false; // directory entry
    }
    return true;
}

bool LooksLikeEmbeddedArchive(const std::string& content) {
    const uint8_t* d = reinterpret_cast<const uint8_t*>(content.data());
    const size_t n = content.size();
    if (n < 4) {
        return false;
    }
    if (memcmp(d, "%PDF", 4) == 0) {
        return true;
    }
    if (d[0] == 'P' && d[1] == 'K' && (d[2] == 3 || d[2] == 5 || d[2] == 7) &&
        (d[3] == 4 || d[3] == 6 || d[3] == 8)) {
        return true;
    }
    if (d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0) {
        return true;
    }
    return false;
}

bool HasLocalName(const pugi::xml_node& node, const char* local) {
    if (node.type() != pugi::node_element) {
        return false;
    }
    const char* name = node.name();
    if (name == nullptr) {
        return false;
    }
    const char* colon = strrchr(name, ':');
    const char* localName = colon ? colon + 1 : name;
    return strcmp(localName, local) == 0;
}

void CollectAllTextIn(const pugi::xml_node& node, std::string& out) {
    for (const pugi::xml_node& child : node.children()) {
        if (child.type() == pugi::node_pcdata || child.type() == pugi::node_cdata) {
            out += child.value();
        } else if (child.type() == pugi::node_element) {
            if (HasLocalName(child, "rPh")) {
                continue; // skip phonetic run text
            }
            CollectAllTextIn(child, out);
        }
    }
}

void CollectTextRecursive(const pugi::xml_node& node, const char* local, std::string& out) {
    for (const pugi::xml_node& child : node.children()) {
        if (child.type() != pugi::node_element) {
            continue;
        }
        if (HasLocalName(child, local)) {
            for (const pugi::xml_node& t : child.children()) {
                if (t.type() == pugi::node_pcdata || t.type() == pugi::node_cdata) {
                    out += t.value();
                }
            }
            out += " ";
        } else if (HasLocalName(child, "br") || HasLocalName(child, "cr")) {
            out += "\n";
        } else if (HasLocalName(child, "tab")) {
            out += "\t";
        }
        CollectTextRecursive(child, local, out);
    }
}

struct Part {
    std::string name;
    uint64_t uncompSize;
    mz_uint index;
};

struct TextSink {
    std::string text;
    bool truncated = false;

    void Append(const std::string& piece) {
        if (truncated || piece.empty()) {
            return;
        }
        if (text.size() + piece.size() > DciLimits_::kMaxExtractedTextBytes) {
            size_t room = DciLimits_::kMaxExtractedTextBytes - text.size();
            text.append(piece, 0, room);
            truncated = true;
            return;
        }
        text += piece;
    }
};

std::string ReadPart(mz_zip_archive* zip, mz_uint index) {
    size_t size = 0;
    void* mem = mz_zip_reader_extract_to_heap(zip, index, &size, 0);
    if (mem == nullptr) {
        return "";
    }
    std::string out(static_cast<const char*>(mem), size);
    mz_free(mem);
    return out;
}

bool ParseXml(const std::string& content, pugi::xml_document& doc) {
    if (content.empty()) {
        return false;
    }
    return static_cast<bool>(doc.load_buffer(content.data(), content.size()));
}

void ForEachLocalName(const pugi::xml_node& node, const char* local,
                      const std::function<void(const pugi::xml_node&)>& fn) {
    if (HasLocalName(node, local)) {
        fn(node);
    }
    for (const pugi::xml_node& child : node.children()) {
        ForEachLocalName(child, local, fn);
    }
}

std::string OoxmlTypeFromContentTypes(const std::string& ctXml) {
    pugi::xml_document doc;
    if (!ParseXml(ctXml, doc)) {
        return "";
    }
    std::string result;
    ForEachLocalName(doc.root(), "Override", [&result](const pugi::xml_node& override) {
        if (!result.empty()) {
            return;
        }
        const char* ct = override.attribute("ContentType").value();
        if (ct == nullptr) {
            return;
        }
        if (strstr(ct, "wordprocessingml") != nullptr || strstr(ct, "wordprocessingdocument") != nullptr) {
            result = "docx";
        } else if (strstr(ct, "spreadsheetml") != nullptr || strstr(ct, "spreadsheet") != nullptr) {
            result = "xlsx";
        } else if (strstr(ct, "presentationml") != nullptr || strstr(ct, "presentation") != nullptr) {
            result = "pptx";
        }
    });
    return result;
}

std::string CellValue(const pugi::xml_node& cell, const std::vector<std::string>& sharedStrings) {
    const char* t = cell.attribute("t").value();
    pugi::xml_node valueNode;
    pugi::xml_node inlineStrNode;
    for (const pugi::xml_node& ch : cell.children()) {
        if (HasLocalName(ch, "v")) {
            valueNode = ch;
        } else if (HasLocalName(ch, "is")) {
            inlineStrNode = ch;
        }
    }

    if (t != nullptr && strcmp(t, "s") == 0) {
        if (valueNode) {
            const char* v = valueNode.text().get();
            if (v == nullptr) {
                return "";
            }
            long idx = strtol(v, nullptr, 10);
            if (idx >= 0 && static_cast<size_t>(idx) < sharedStrings.size()) {
                return sharedStrings[static_cast<size_t>(idx)];
            }
        }
        return "";
    }
    if (t != nullptr && strcmp(t, "inlineStr") == 0) {
        std::string s;
        if (inlineStrNode) {
            CollectAllTextIn(inlineStrNode, s);
        }
        return s;
    }
    if (t != nullptr && strcmp(t, "b") == 0) {
        if (valueNode) {
            const char* v = valueNode.text().get();
            if (v == nullptr) {
                return "";
            }
            std::string sv = v;
            return (sv == "1" || sv == "TRUE" || sv == "true") ? "TRUE" : "FALSE";
        }
        return "";
    }
    if (t != nullptr && strcmp(t, "e") == 0) {
        return ""; // error value (e.g. #DIV/0!) - not sensitive, skip
    }
    if (valueNode) {
        const char* v = valueNode.text().get();
        return v != nullptr ? std::string(v) : std::string();
    }
    return "";
}

int NumericSuffix(const std::string& name) {
    // Extract the trailing number from names like "ppt/slides/slide12.xml".
    size_t dot = name.rfind('.');
    size_t start = dot == std::string::npos ? name.size() : dot;
    while (start > 0 && name[start - 1] >= '0' && name[start - 1] <= '9') {
        --start;
    }
    return start < dot ? atoi(name.c_str() + start) : 0;
}

// ============================================================================
// OOXML EXTRACTORS
// ============================================================================

bool IsDocxTextPart(const std::string& name) {
    auto endsWithXml = [&name]() {
        return name.size() > 4 && name.rfind(".xml") == name.size() - 4;
    };
    if (name == "word/document.xml" || name == "word/footnotes.xml" || name == "word/endnotes.xml") {
        return true;
    }
    return endsWithXml() &&
           (name.rfind("word/header", 0) == 0 || name.rfind("word/footer", 0) == 0);
}

void ExtractDocxParts(
    mz_zip_archive* zip,
    const std::map<std::string, mz_uint>& indexByName,
    const DciContext& ctx,
    TextSink& sink,
    ExtractionResult& res)
{
    for (const auto& kv : indexByName) {
        const std::string& name = kv.first;
        if (!IsDocxTextPart(name)) {
            continue;
        }
        if (ctx.TimeExpired()) {
            res.errorCategory = DciError::kTimeout;
            res.warnings.push_back("deadline_exceeded");
            return;
        }
        std::string content = ReadPart(zip, kv.second);
        if (content.empty()) {
            continue;
        }
        if (LooksLikeEmbeddedArchive(content)) {
            res.warnings.push_back("nested_archive_rejected");
            continue;
        }
        pugi::xml_document doc;
        if (!ParseXml(content, doc)) {
            res.warnings.push_back("xml_parse_failed");
            continue;
        }
        std::string partText;
        CollectTextRecursive(doc.root(), "t", partText);
        sink.Append(partText);
        if (sink.truncated) {
            res.truncationStatus = true;
            return;
        }
    }
}

void ExtractXlsxParts(
    mz_zip_archive* zip,
    const std::map<std::string, mz_uint>& indexByName,
    const DciContext& ctx,
    TextSink& sink,
    ExtractionResult& res)
{
    // Shared strings.
    std::vector<std::string> sharedStrings;
    auto it = indexByName.find("xl/sharedStrings.xml");
    if (it != indexByName.end()) {
        if (ctx.TimeExpired()) {
            res.errorCategory = DciError::kTimeout;
            res.warnings.push_back("deadline_exceeded");
            return;
        }
        std::string content = ReadPart(zip, it->second);
        pugi::xml_document doc;
        if (ParseXml(content, doc)) {
            ForEachLocalName(doc.root(), "si", [&sharedStrings](const pugi::xml_node& si) {
                std::string s;
                CollectAllTextIn(si, s);
                sharedStrings.push_back(s);
            });
        }
    }

    // Discover worksheets via workbook relationships, falling back to globbing.
    std::vector<std::string> sheets;
    auto relIt = indexByName.find("xl/_rels/workbook.xml.rels");
    if (relIt != indexByName.end()) {
        std::string rels = ReadPart(zip, relIt->second);
        pugi::xml_document doc;
        if (ParseXml(rels, doc)) {
            ForEachLocalName(doc.root(), "Relationship", [&sheets](const pugi::xml_node& rel) {
                const char* target = rel.attribute("Target").value();
                if (target == nullptr) {
                    return;
                }
                std::string t = target;
                if (!t.empty() && t[0] == '/') {
                    t = t.substr(1);
                }
                if (t.rfind("xl/worksheets/", 0) != 0) {
                    if (t.rfind("worksheets/", 0) == 0) {
                        t = "xl/" + t;
                    } else {
                        return;
                    }
                }
                sheets.push_back(t);
            });
        }
    }
    if (sheets.empty()) {
        for (const auto& kv : indexByName) {
            if (kv.first.rfind("xl/worksheets/sheet", 0) == 0 &&
                kv.first.rfind(".xml") == kv.first.size() - 4) {
                sheets.push_back(kv.first);
            }
        }
    }
    std::sort(sheets.begin(), sheets.end(), [](const std::string& a, const std::string& b) {
        return NumericSuffix(a) < NumericSuffix(b);
    });

    for (const std::string& sheetName : sheets) {
        if (sink.truncated) {
            res.truncationStatus = true;
            return;
        }
        if (ctx.TimeExpired()) {
            res.errorCategory = DciError::kTimeout;
            res.warnings.push_back("deadline_exceeded");
            return;
        }
        auto idxIt = indexByName.find(sheetName);
        if (idxIt == indexByName.end()) {
            continue;
        }
        std::string content = ReadPart(zip, idxIt->second);
        pugi::xml_document doc;
        if (!ParseXml(content, doc)) {
            res.warnings.push_back("xml_parse_failed");
            continue;
        }

        pugi::xml_node sheetData;
        for (const pugi::xml_node& ch : doc.root().children()) {
            if (HasLocalName(ch, "worksheet")) {
                for (const pugi::xml_node& inner : ch.children()) {
                    if (HasLocalName(inner, "sheetData")) {
                        sheetData = inner;
                        break;
                    }
                }
                break;
            }
        }

        for (const pugi::xml_node& row : sheetData.children()) {
            if (!HasLocalName(row, "row")) {
                continue;
            }
            std::string rowText;
            bool first = true;
            for (const pugi::xml_node& cell : row.children()) {
                if (!HasLocalName(cell, "c")) {
                    continue;
                }
                std::string val = CellValue(cell, sharedStrings);
                if (val.empty()) {
                    continue;
                }
                if (!first) {
                    rowText += "|";
                }
                first = false;
                rowText += val;
            }
            sink.Append(rowText);
            sink.Append("\n");
            if (sink.truncated) {
                res.truncationStatus = true;
                return;
            }
        }
    }
}

void ExtractPptxParts(
    mz_zip_archive* zip,
    const std::map<std::string, mz_uint>& indexByName,
    const DciContext& ctx,
    TextSink& sink,
    ExtractionResult& res)
{
    // Follow presentation relationships to discover slide order.
    std::vector<std::string> slides;
    auto relIt = indexByName.find("ppt/_rels/presentation.xml.rels");
    if (relIt != indexByName.end()) {
        std::string rels = ReadPart(zip, relIt->second);
        pugi::xml_document doc;
        if (ParseXml(rels, doc)) {
            ForEachLocalName(doc.root(), "Relationship", [&slides](const pugi::xml_node& rel) {
                const char* type = rel.attribute("Type").value();
                const char* target = rel.attribute("Target").value();
                if (type == nullptr || target == nullptr || strstr(type, "/slide") == nullptr) {
                    return;
                }
                std::string t = target;
                if (!t.empty() && t[0] == '/') {
                    t = t.substr(1);
                } else if (t.rfind("slides/", 0) == 0) {
                    t = "ppt/" + t;
                }
                if (t.rfind("ppt/slides/slide", 0) == 0) {
                    slides.push_back(t);
                }
            });
        }
    }
    if (slides.empty()) {
        for (const auto& kv : indexByName) {
            if (kv.first.rfind("ppt/slides/slide", 0) == 0 &&
                kv.first.rfind(".xml") == kv.first.size() - 4) {
                slides.push_back(kv.first);
            }
        }
    }
    std::sort(slides.begin(), slides.end(), [](const std::string& a, const std::string& b) {
        return NumericSuffix(a) < NumericSuffix(b);
    });

    for (const std::string& slideName : slides) {
        if (sink.truncated) {
            res.truncationStatus = true;
            return;
        }
        if (ctx.TimeExpired()) {
            res.errorCategory = DciError::kTimeout;
            res.warnings.push_back("deadline_exceeded");
            return;
        }
        auto idxIt = indexByName.find(slideName);
        if (idxIt == indexByName.end()) {
            continue;
        }
        std::string content = ReadPart(zip, idxIt->second);
        pugi::xml_document doc;
        if (!ParseXml(content, doc)) {
            res.warnings.push_back("xml_parse_failed");
            continue;
        }
        std::string partText;
        CollectTextRecursive(doc.root(), "t", partText);
        sink.Append(partText);
        sink.Append("\n");
        if (sink.truncated) {
            res.truncationStatus = true;
            return;
        }
    }
}

ExtractionResult ExtractOoxml(const std::string& data, const DciContext& ctx) {
    ExtractionResult res;

    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, data.data(), data.size(), 0)) {
        res.errorCategory = DciError::kCorrupt;
        res.warnings.push_back("invalid_zip_archive");
        return res;
    }

    const mz_uint count = mz_zip_reader_get_num_files(&zip);
    if (count > DciLimits_::kMaxArchiveEntries) {
        mz_zip_reader_end(&zip);
        res.errorCategory = DciError::kTooManyEntries;
        res.warnings.push_back("archive_entry_count_exceeds_limit");
        return res;
    }

    if (ctx.TimeExpired()) {
        mz_zip_reader_end(&zip);
        res.errorCategory = DciError::kTimeout;
        res.warnings.push_back("deadline_exceeded");
        return res;
    }

    std::map<std::string, mz_uint> indexByName;
    std::string contentTypeXml;
    bool hasContentTypes = false;
    uint64_t totalUncompressed = 0;
    uint64_t totalCompressed = 0;

    for (mz_uint i = 0; i < count; ++i) {
        mz_zip_archive_file_stat st;
        memset(&st, 0, sizeof(st));
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            res.warnings.push_back("unreadable_zip_entry");
            continue;
        }
        if (st.m_is_directory) {
            continue;
        }
        std::string name = st.m_filename != nullptr ? st.m_filename : "";
        if (!ValidateEntryName(name)) {
            res.warnings.push_back("rejected_malformed_entry");
            continue;
        }

        totalUncompressed += st.m_uncomp_size;
        totalCompressed += st.m_comp_size;
        if (totalUncompressed > DciLimits_::kMaxUncompressedBytes) {
            mz_zip_reader_end(&zip);
            res.errorCategory = DciError::kZipBomb;
            res.warnings.push_back("uncompressed_size_exceeds_limit");
            return res;
        }
        if (totalCompressed > 0 && totalUncompressed / totalCompressed > DciLimits_::kMaxCompressionRatio) {
            mz_zip_reader_end(&zip);
            res.errorCategory = DciError::kZipBomb;
            res.warnings.push_back("compression_ratio_exceeds_limit");
            return res;
        }

        if (name == "[Content_Types].xml") {
            std::string content = ReadPart(&zip, i);
            if (!content.empty()) {
                contentTypeXml = content;
                hasContentTypes = true;
            }
            continue;
        }

        indexByName[name] = i;
        if (ctx.TimeExpired()) {
            mz_zip_reader_end(&zip);
            res.errorCategory = DciError::kTimeout;
            res.warnings.push_back("deadline_exceeded");
            return res;
        }
    }

    if (!hasContentTypes) {
        mz_zip_reader_end(&zip);
        res.errorCategory = DciError::kUnsupported;
        res.warnings.push_back("missing_content_types");
        return res;
    }

    std::string ooxmlType = OoxmlTypeFromContentTypes(contentTypeXml);
    if (ooxmlType.empty()) {
        mz_zip_reader_end(&zip);
        res.errorCategory = DciError::kUnsupported;
        res.warnings.push_back("not_ooxml_archive");
        return res;
    }
    res.fileType = ooxmlType;

    TextSink sink;
    if (ooxmlType == "docx") {
        ExtractDocxParts(&zip, indexByName, ctx, sink, res);
    } else if (ooxmlType == "xlsx") {
        ExtractXlsxParts(&zip, indexByName, ctx, sink, res);
    } else if (ooxmlType == "pptx") {
        ExtractPptxParts(&zip, indexByName, ctx, sink, res);
    }

    if (res.errorCategory == DciError::kTimeout) {
        mz_zip_reader_end(&zip);
        return res;
    }

    res.extractedText = sink.text;
    res.truncationStatus = sink.truncated;
    mz_zip_reader_end(&zip);
    return res;
}

} // namespace

// ============================================================================
// DeepContentInspector PUBLIC API
// ============================================================================

DeepContentInspector::DeepContentInspector() = default;

void DeepContentInspector::SetDeadline(std::chrono::milliseconds deadline) {
    deadline_ = deadline;
}

std::chrono::milliseconds DeepContentInspector::GetDeadline() const {
    return deadline_;
}

void DeepContentInspector::Cancel() {
    cancelled_.store(true, std::memory_order_relaxed);
}

void DeepContentInspector::ResetCancel() {
    cancelled_.store(false, std::memory_order_relaxed);
}

bool DeepContentInspector::DeadlineExpired() const {
    return cancelled_.load(std::memory_order_relaxed) || deadline_.count() <= 0;
}

ExtractionResult DeepContentInspector::ExtractDocument(const std::wstring& filePath) {
    DciContext ctx{std::chrono::steady_clock::now(), deadline_, &cancelled_};

    ExtractionResult res;

    std::string raw;
    std::string readErr;
    if (!ReadFileBounded(filePath, DciLimits_::kMaxInputBytes, raw, readErr)) {
        res.errorCategory = readErr;
        if (readErr == DciError::kTooLarge) {
            res.warnings.push_back("input_exceeds_max_size");
        }
        return res;
    }
    if (raw.empty()) {
        res.fileType = "text";
        return res;
    }
    if (ctx.TimeExpired()) {
        res.errorCategory = DciError::kTimeout;
        res.warnings.push_back("deadline_exceeded");
        return res;
    }

    const uint8_t* d = reinterpret_cast<const uint8_t*>(raw.data());
    const size_t n = raw.size();

    // PDF signature: 25 50 44 46 ("%PDF")
    if (n >= 4 && memcmp(d, "%PDF", 4) == 0) {
        res.fileType = "pdf";
        res.errorCategory = DciError::kUnsupported;
        res.warnings.push_back("pdf_extraction_not_implemented_in_this_phase");
        return res;
    }

    // OLE compound document: legacy Office (doc/xls/ppt) or encrypted OOXML.
    if (n >= 8 && d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0 &&
        d[4] == 0xA1 && d[5] == 0xB1 && d[6] == 0x1A && d[7] == 0xE1) {
        res.fileType = "ole";
        const size_t probe = std::min(n, static_cast<size_t>(4096));
        std::string head(reinterpret_cast<const char*>(d), probe);
        if (head.find("EncryptionInfo") != std::string::npos ||
            head.find("EncryptedPackage") != std::string::npos) {
            res.errorCategory = DciError::kEncrypted;
            res.warnings.push_back("encrypted_ooxml_package");
        } else {
            res.errorCategory = DciError::kUnsupported;
            res.warnings.push_back("legacy_ole_compound_format");
        }
        return res;
    }

    // ZIP signatures: PK\x03\x04 (local header), PK\x05\x06 (EOCD), PK\x07\x08 (descriptor).
    if (n >= 4 && d[0] == 'P' && d[1] == 'K' &&
        (d[2] == 0x03 || d[2] == 0x05 || d[2] == 0x07) &&
        (d[3] == 0x04 || d[3] == 0x06 || d[3] == 0x08)) {
        res.fileType = "zip";
        return ExtractOoxml(raw, ctx);
    }

    // Otherwise treat as plain text (BOMs, bounded UTF-8 validation, control bytes).
    return ExtractPlainText(raw, ctx);
}

// ============================================================================
// PII SCANNING (RE2)
// ============================================================================

bool DeepContentInspector::IsValidLuhn(const std::string& digits) {
    if (digits.empty()) {
        return false;
    }
    int sum = 0;
    bool doubleDigit = false;
    for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i) {
        int n = digits[static_cast<size_t>(i)] - '0';
        if (n < 0 || n > 9) {
            return false;
        }
        if (doubleDigit) {
            n *= 2;
            if (n > 9) {
                n -= 9;
            }
        }
        sum += n;
        doubleDigit = !doubleDigit;
    }
    return (sum % 10) == 0;
}

namespace {

// One internal scanning pass shared by ScanTextForPII and ScanTextForPIITyped
// so the detectors are never duplicated. Raw values are allowed here briefly
// but never escape into the typed findings, logs, telemetry or persistence.
struct RawMatch {
    std::string value;
    DeepContentInspector::PiiEntity entity = DeepContentInspector::PiiEntity::Unknown;
    bool hard = false;                 // Luhn-validated credit card
    size_t start = 0;
    size_t end = 0;
};

// Returns false if the scanner itself failed (patterns could not compile).
// Mirrors the previous std::regex behavior exactly.
bool ScanAllText(const std::string& text, std::vector<RawMatch>& out) {
    using PiiEntity = DeepContentInspector::PiiEntity;

    // Patterns are identical to the pre-existing std::regex implementation.
    static const re2::RE2 ccRegex(R"(\b((?:\d[ -]*?){13,16})\b)");
    static const re2::RE2 ssnRegex(R"(\b(\d{3}-\d{2}-\d{4})\b)");
    static const re2::RE2 apiKeyRegex(
        R"(\b(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48})\b)");

    if (!ccRegex.ok() || !ssnRegex.ok() || !apiKeyRegex.ok()) {
        LOG_ERROR("DCI: failed to compile RE2 PII patterns");
        return false;
    }

    auto consumeAll = [&out, &text](const re2::RE2& re, PiiEntity entity, bool luhnCheck) {
        const char* base = text.data();
        re2::StringPiece input(text);
        re2::StringPiece m;
        while (re2::RE2::FindAndConsume(&input, re, &m)) {
            std::string candidate(m.data(), m.size());
            bool hard = false;
            if (luhnCheck) {
                std::string digits;
                digits.reserve(candidate.size());
                for (char c : candidate) {
                    if (c >= '0' && c <= '9') {
                        digits.push_back(c);
                    }
                }
                if (!DeepContentInspector::IsValidLuhn(digits)) {
                    if (m.size() == 0) input.remove_prefix(1);
                    continue; // not a valid card: skip
                }
                hard = true; // Luhn-validated => hard evidence
            }
            RawMatch rm;
            rm.value = std::move(candidate);
            rm.entity = entity;
            rm.hard = hard;
            rm.start = static_cast<size_t>(m.data() - base);
            rm.end = rm.start + m.size();
            out.push_back(std::move(rm));
            if (m.size() == 0) {
                input.remove_prefix(1); // guard against empty-match loops
            }
        }
    };

    consumeAll(ccRegex, PiiEntity::CreditCard, true);
    consumeAll(ssnRegex, PiiEntity::Ssn, false);
    consumeAll(apiKeyRegex, PiiEntity::ApiKey, false);

    return true;
}

} // namespace

std::vector<std::string> DeepContentInspector::ScanTextForPII(const std::string& text) {
    std::vector<RawMatch> raw;
    if (!ScanAllText(text, raw)) {
        return {};
    }
    std::vector<std::string> matches;
    matches.reserve(raw.size());
    for (auto& r : raw) {
        matches.push_back(std::move(r.value));
    }
    return matches;
}

DeepContentInspector::PiiScanResult DeepContentInspector::ScanTextForPIITyped(
    const std::string& text)
{
    PiiScanResult result;
    std::vector<RawMatch> raw;
    if (!ScanAllText(text, raw)) {
        result.scannerError = true;
        return result;
    }

    // Aggregate per entity: count occurrences, keep first offsets, and flag
    // hard evidence if ANY occurrence of that entity was validated.
    for (auto& r : raw) {
        auto it = std::find_if(result.findings.begin(), result.findings.end(),
            [&](const PiiFinding& f) { return f.entity == r.entity; });
        if (it == result.findings.end()) {
            PiiFinding f;
            f.entity = r.entity;
            f.count = 1;
            f.startOffset = r.start;
            f.endOffset = r.end;
            f.hardEvidence = r.hard;
            f.strength = r.hard ? EvidenceStrength::Strong : EvidenceStrength::Moderate;
            result.findings.push_back(f);
        } else {
            it->count += 1;
            if (r.hard) {
                it->hardEvidence = true;
                it->strength = EvidenceStrength::Strong;
            }
        }
    }
    return result;
}

const char* DeepContentInspector::PiiEntityName(PiiEntity entity) {
    switch (entity) {
        case PiiEntity::CreditCard: return "CREDIT_CARD";
        case PiiEntity::Ssn:        return "SSN";
        case PiiEntity::ApiKey:     return "API_KEY";
        default:                    return "UNKNOWN";
    }
}

std::string DeepContentInspector::MaskSensitiveData(const std::string& text) {
    static const re2::RE2 ssnRegex(R"(\b(\d{3})-(\d{2})-(\d{4})\b)");
    static const re2::RE2 ccRegex(R"(\b((?:\d[ -]*?){13,16})\b)");
    static const re2::RE2 apiKeyRegex(
        R"(\b(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48})\b)");

    std::string masked = text;

    if (ssnRegex.ok()) {
        re2::RE2::GlobalReplace(&masked, ssnRegex, "***-**-\\3");
    }

    if (ccRegex.ok()) {
        // Keep only the last four digits of each card, mirroring the previous
        // std::regex behavior.
        std::string result;
        size_t lastPos = 0;
        const char* base = masked.data();
        re2::StringPiece input(masked);
        re2::StringPiece m;
        while (re2::RE2::FindAndConsume(&input, ccRegex, &m)) {
            size_t pos = static_cast<size_t>(m.data() - base);
            result.append(masked, lastPos, pos - lastPos);
            std::string card(m.data(), m.size());
            std::string digits;
            for (char c : card) {
                if (c >= '0' && c <= '9') {
                    digits.push_back(c);
                }
            }
            result += "****";
            if (digits.size() >= 4) {
                result += digits.substr(digits.size() - 4);
            }
            lastPos = pos + m.size();
            if (m.size() == 0) {
                input.remove_prefix(1);
            }
        }
        if (lastPos == 0) {
            result = masked;
        } else {
            result.append(masked, lastPos, std::string::npos);
        }
        masked = std::move(result);
    }

    if (apiKeyRegex.ok()) {
        re2::RE2::GlobalReplace(&masked, apiKeyRegex, "***REDACTED***");
    }

    return masked;
}

} // namespace DLP
} // namespace Pritrak