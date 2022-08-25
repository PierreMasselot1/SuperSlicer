#include "Raise3D.hpp"

#include <algorithm>
#include <sstream>
#include <exception>
#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/uuid/detail/sha1.hpp>
#include <boost/algorithm/hex.hpp>

#include <wx/progdlg.h>

#include "libslic3r/PrintConfig.hpp"
#include "slic3r/GUI/I18N.hpp"
#include "slic3r/GUI/GUI.hpp"
#include "slic3r/GUI/format.hpp"
#include "Http.hpp"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
static std::string token;

namespace Slic3r {
static std::string token;

Raise3D::Raise3D(DynamicPrintConfig *config)
    : host(config->opt_string("print_host"))
    , apikey(config->opt_string("printhost_apikey"))
    , cafile(config->opt_string("printhost_cafile"))
    , port(config->opt_string("printhost_port"))
{}

const char *Raise3D::get_name() const { return "Raise3D"; }

bool Raise3D::test(wxString &msg) const
{
    // Since all commands call test before running, test is going to call
    // the login endpoint, and if a token is received back from the
    // printer it means that login was successful

    const char *name = get_name();

    bool res = true;
    auto url = make_url("login");

    using namespace std::chrono;

    uint64_t ms = duration_cast<milliseconds>(
                      system_clock::now().time_since_epoch())
                      .count();
    std::cout << ms << " milliseconds since the Epoch\n";

    uint64_t sec =
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    std::cout << sec
              << " seconds since the Epoch\n"; // boost::uuids::detail::md5 md5;
    std::ostringstream os;
    os << sec;
    const std::string timestamp = os.str();
    // boost::uuids::detail::sha1 sha1;
    // boost::md5(
    //  (boost::format("?password=%1%&timestamp=%2%") % apikey % timestamp)
    //        .str());

    // Compute an MD5 hash and convert to std::string.
    std::string sign_string = (boost::format("password=%1%&timestamp=%2%") %
                               apikey % timestamp)
                                  .str();

    boost::uuids::detail::sha1 sha1;
    sha1.process_bytes(sign_string.data(), sign_string.size());
    unsigned hash1[5] = {0};
    sha1.get_digest(hash1);

    // Back to string
    char buf[41] = {0};

    for (int i = 0; i < 5; i++) {
        std::sprintf(buf + (i << 3), "%08x", hash1[i]);
    }

    std::string sha1result = std::string(buf);

    boost::uuids::detail::md5              hash;
    boost::uuids::detail::md5::digest_type digest;

    hash.process_bytes(sha1result.data(), sha1result.size());
    hash.get_digest(digest);

    const auto  intDigest = reinterpret_cast<const int *>(&digest);
    std::string result;
    boost::algorithm::hex(intDigest,
                          intDigest +
                              (sizeof(boost::uuids::detail::md5::digest_type) /
                               sizeof(int)),
                          std::back_inserter(result));
    boost::to_lower(result);

    const std::string sign = result;
    url                    = url +
          (boost::format("?sign=%1%&timestamp=%2%") % sign % timestamp).str();

    BOOST_LOG_TRIVIAL(info)
        << boost::format("%1%: List version at: %2%") % name % url;

    auto http = Http::get(std::move(url));

    http.on_error([&](std::string body, std::string error, unsigned status) {
            BOOST_LOG_TRIVIAL(error)
                << boost::format("%1%: Error logging into the printer") %
                       name;
            res = false;
            msg = format_error(body, error, status);
        })
        .on_complete([&, this](std::string body, unsigned) {
            try {
                std::stringstream ss(body);
                pt::ptree         ptree;
                pt::read_json(ss, ptree);

                const std::string text = ptree.get_value<std::string>(
                    "data.token");
                token = text;
                ;

            } catch (const std::exception &) {
                res = false;
                msg = "Could not parse server response";
            }
        })
        .perform_sync();

    return res;
}

wxString Raise3D::get_test_ok_msg() const
{
    return _(L("Connection to Raise3D works correctly."));
}

wxString Raise3D::get_test_failed_msg(wxString &msg) const
{
    return GUI::from_u8((boost::format("%s: %s\n\n%s") %
                         _utf8(L("Could not connect to Raise3D")) %
                         std::string(msg.ToUTF8()) %
                         _utf8(L("Note: make sure that the API is "
                                 "enabled on your 3D printer")))
                            .str());
}

bool Raise3D::upload(PrintHostUpload upload_data,
                     ProgressFn      prorgess_fn,
                     ErrorFn         error_fn) const
{
    const char *name = get_name();

    const auto upload_filename    = upload_data.upload_path.filename();
    const auto upload_parent_path = upload_data.upload_path.parent_path();
    const std::string upload_path = "Local / webapi_store";

    wxString test_msg;
    if (!test(test_msg)) {
        error_fn(std::move(test_msg));
        return false;
    }

    bool res = true;

    auto url = make_url(
        (boost::format("fileops/upload?token=%1%") % token).str());
    BOOST_LOG_TRIVIAL(info)
        << boost::format("%1%: Uploading file %2% at %3%, filename: %4%, "
                         "path: %5%, print: %6%, group: %7%") %
               name % upload_data.source_path % url %
               upload_filename.string() % upload_parent_path.string() %
               (upload_data.post_action ==
                        PrintHostPostUploadAction::StartPrint ?
                    "true" :
                    "false") %
               upload_data.group;

    auto              http = Http::post(std::move(url));
    const std::string desc =
        (boost::format("{\"dir_path\": \"%1%\"}") % upload_path).str();
    http.form_add("desc", desc);

    http.form_add("name", "file")
        .form_add("filename",
                  upload_filename.string()) // this might already be the behavior
                                            // of form_add_file, needs testing
        .form_add_file("filename", upload_data.source_path.string(),
                       upload_filename.string())
        .on_complete([&](std::string body, unsigned status) {
            BOOST_LOG_TRIVIAL(debug)
                << boost::format("%1%: File uploaded: HTTP %2%: %3%") % name %
                       status % body;
        })
        .on_error([&](std::string body, std::string error, unsigned status) {
            BOOST_LOG_TRIVIAL(error)
                << boost::format("%1%: Error uploading file: %2%, HTTP %3%, "
                                 "body: `%4%`") %
                       name % error % status % body;
            error_fn(format_error(body, error, status));
            res = false;
        })
        .on_progress([&](Http::Progress progress, bool &cancel) {
            prorgess_fn(std::move(progress), cancel);
            if (cancel) {
                // Upload was canceled
                BOOST_LOG_TRIVIAL(info) << "Raise3D: Upload canceled";
                res = false;
            }
        })
        .perform_sync();

    return res;
}

std::string Raise3D::make_url(const std::string &path) const
{
    if (host.find("http://") == 0 || host.find("https://") == 0) {
        if (host.back() == '/') {
            return (boost::format("%1%/v1/%2%") % host % path).str();
        } else {
            return (boost::format("%1%/v1/%2%") % host % path).str();
        }
    } else {
        return (boost::format("http://%1%/v1/%2%") % host % path).str();
    }
}

} // namespace Slic3r
