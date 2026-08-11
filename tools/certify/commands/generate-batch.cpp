#include "generate-batch.hpp"
#include "utils.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/variant/get.hpp>
#include <chrono>
#include <cryptopp/cryptlib.h>
#include <filesystem>
#include <iostream>
#include <set>
#include <yaml-cpp/yaml.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <vanetza/security/v2/subject_attribute.hpp>
#include <vanetza/security/v2/subject_info.hpp>

namespace aid = vanetza::aid;
namespace po = boost::program_options;
namespace fs = std::filesystem;
using namespace vanetza::security;

bool GenerateBatchCommand::parse(const std::vector<std::string> &opts) {
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("config", po::value<std::string>(&config_file)->required(), "Configuration file (YAML-like format).")
        ("dry-run", po::bool_switch(&dry_run), "Parse config and show what would be generated without creating files.")
        ("verbose,v", po::bool_switch(&verbose), "Verbose output.")
        ("stations", po::value<std::vector<std::string>>(&filter_stations)->multitoken(),
         "Generate only for specific station IDs (space-separated).");

    po::positional_options_description pos;
    pos.add("config", 1);

    po::variables_map vm;
    po::store(po::command_line_parser(opts).options(desc).positional(pos).run(), vm);

    if (vm.count("help")) {
        std::cerr << desc << std::endl;
        return false;
    }

    try {
        po::notify(vm);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl << std::endl << desc << std::endl;
        return false;
    }

    return true;
}

// yaml-cpp parser
bool GenerateBatchCommand::parse_config(const std::string& filename, BatchConfig& config) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(filename);
    } catch (const YAML::Exception& e) {
        std::cerr << "Failed to parse config file: " << e.what() << std::endl;
        return false;
    }

    // Parse defaults
    if (root["defaults"]) {
        auto defaults = root["defaults"];
        if (defaults["sign_key"])      config.sign_key    = defaults["sign_key"].as<std::string>();
        if (defaults["sign_cert"])     config.sign_cert   = defaults["sign_cert"].as<std::string>();
        if (defaults["output_dir"])    config.output_dir  = defaults["output_dir"].as<std::string>();
        if (defaults["validity_days"]) config.validity_days = defaults["validity_days"].as<int>();
    }

    // Parse profiles
    if (root["profiles"]) {
        for (const auto& entry : root["profiles"]) {
            std::string name = entry.first.as<std::string>();
            const auto& node = entry.second;
            PermissionProfile profile;
            if (node["cam_permissions"])  profile.cam_permissions  = node["cam_permissions"].as<std::string>();
            if (node["denm_permissions"]) profile.denm_permissions = node["denm_permissions"].as<std::string>();
            if (node["permit_vam"])       profile.permit_vam       = node["permit_vam"].as<bool>();
            if (node["permit_cpm"])       profile.permit_cpm       = node["permit_cpm"].as<bool>();
            if (node["permit_gn_mgmt"])   profile.permit_gn_mgmt   = node["permit_gn_mgmt"].as<bool>();
            config.profiles[name] = profile;
        }
    }

    // Parse stations
    if (root["stations"]) {
        for (const auto& node : root["stations"]) {
            StationConfig station;
            if (node["station_id"])  station.station_id  = node["station_id"].as<std::string>();
            if (node["name"])        station.name        = node["name"].as<std::string>();
            if (node["subject_key"]) station.subject_key = node["subject_key"].as<std::string>();
            if (node["profile"])     station.profile     = node["profile"].as<std::string>();
            if (node["cam_permissions"]) {
                station.cam_permissions = node["cam_permissions"].as<std::string>();
                station.has_inline_permissions = true;
            }
            if (node["denm_permissions"]) {
                station.denm_permissions = node["denm_permissions"].as<std::string>();
                station.has_inline_permissions = true;
            }
            if (node["permit_vam"]) {
                station.permit_vam = node["permit_vam"].as<bool>();
                station.has_inline_permissions = true;
            }
            if (node["permit_cpm"]) {
                station.permit_cpm = node["permit_cpm"].as<bool>();
                station.has_inline_permissions = true;
            }
            if (node["permit_gn_mgmt"]) {
                station.permit_gn_mgmt = node["permit_gn_mgmt"].as<bool>();
                station.has_inline_permissions = true;
            }
            config.stations.push_back(station);
        }
    }

    return true;
}

int GenerateBatchCommand::generate_ticket(const BatchConfig& config, const StationConfig& station) {
    auto backend = create_backend_or_throw("default");

    if (verbose) {
        std::cout << "  Loading keys... ";
    }

    auto sign_key = v2::load_private_key_from_file(config.sign_key);
    ecdsa256::PublicKey subject_key;

    try {
        auto subject_private_key = v2::load_private_key_from_file(station.subject_key);
        subject_key = subject_private_key.public_key;
    } catch (CryptoPP::BERDecodeErr &e) {
        auto subject_key_etsi = v2::load_public_key_from_file(station.subject_key);
        if (v2::get_type(subject_key_etsi) != v2::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256) {
            std::cerr << "Wrong public key algorithm for station " << station.station_id << std::endl;
            return 1;
        }

        auto subject_key_etsi_ecdsa = boost::get<v2::ecdsa_nistp256_with_sha256>(subject_key_etsi);
        if (v2::get_type(subject_key_etsi_ecdsa.public_key) != v2::EccPointType::Uncompressed) {
            std::cerr << "Unsupported ECC point type for station " << station.station_id << ", must be uncompressed." << std::endl;
            return 1;
        }

        subject_key = ecdsa256::create_public_key(boost::get<Uncompressed>(subject_key_etsi_ecdsa.public_key));
    }

    if (verbose) {
        std::cout << "OK" << std::endl;
    }

    auto sign_cert = v2::load_certificate_from_file(config.sign_cert);
    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    // Determine permissions (inline overrides profile)
    std::string cam_permissions;
    std::string denm_permissions;
    bool permit_vam = false;
    bool permit_cpm = false;
    bool permit_gn_mgmt = false;

    if (station.has_inline_permissions) {
        cam_permissions = station.cam_permissions;
        denm_permissions = station.denm_permissions;
        permit_vam = station.permit_vam;
        permit_cpm = station.permit_cpm;
        permit_gn_mgmt = station.permit_gn_mgmt;
    } else if (!station.profile.empty()) {
        auto it = config.profiles.find(station.profile);
        if (it == config.profiles.end()) {
            std::cerr << "Profile '" << station.profile << "' not found for station " << station.station_id << std::endl;
            return 1;
        }
        const auto& profile = it->second;
        cam_permissions = profile.cam_permissions;
        denm_permissions = profile.denm_permissions;
        permit_vam = profile.permit_vam;
        permit_cpm = profile.permit_cpm;
        permit_gn_mgmt = profile.permit_gn_mgmt;
    }

    auto cam_ssps = vanetza::ByteBuffer({1, 0, 0});      // no special permissions by default
    auto denm_ssps = vanetza::ByteBuffer({1, 0, 0, 0});  // no special permissions by default

    if (!cam_permissions.empty()) {
        permission_string_to_buffer(cam_permissions, cam_ssps);
    }

    if (!denm_permissions.empty()) {
        permission_string_to_buffer(denm_permissions, denm_ssps);
    }

    v2::Certificate certificate;
    std::list<v2::ItsAidSsp> certificate_ssp;

    // CAM permissions (ETSI EN 302 637-2 V1.3.1)
    v2::ItsAidSsp certificate_ssp_ca;
    certificate_ssp_ca.its_aid = v2::IntX(aid::CA);
    certificate_ssp_ca.service_specific_permissions = cam_ssps;
    certificate_ssp.push_back(certificate_ssp_ca);

    // DENM permissions (ETSI EN 302 637-3 V1.2.2)
    v2::ItsAidSsp certificate_ssp_den;
    certificate_ssp_den.its_aid = v2::IntX(aid::DEN);
    certificate_ssp_den.service_specific_permissions = denm_ssps;
    certificate_ssp.push_back(certificate_ssp_den);

    if (permit_vam) {
        // VAM permissions (ETSI TS 103 300-3 V2.2.1)
        auto vam_ssps = vanetza::ByteBuffer({1});
        v2::ItsAidSsp certificate_ssp_vbs;
        certificate_ssp_vbs.its_aid = v2::IntX(aid::VRU);
        certificate_ssp_vbs.service_specific_permissions = vam_ssps;
        certificate_ssp.push_back(certificate_ssp_vbs);
    }

    if (permit_cpm) {
        // CPM permissions (ETSI TS 103 324 V2.1.1)
        auto cp_ssps = vanetza::ByteBuffer({1});
        v2::ItsAidSsp certificate_ssp_cp;
        certificate_ssp_cp.its_aid = v2::IntX(aid::CP);
        certificate_ssp_cp.service_specific_permissions = cp_ssps;
        certificate_ssp.push_back(certificate_ssp_cp);
    }

    if (permit_gn_mgmt) {
        certificate_ssp.push_back({v2::IntX(aid::GN_MGMT), vanetza::ByteBuffer{}});
    }

    certificate.signer_info = calculate_hash(sign_cert);
    certificate.subject_info.subject_type = v2::SubjectType::Authorization_Ticket;
    certificate.subject_attributes.push_back(v2::SubjectAssurance(0x00));
    certificate.subject_attributes.push_back(certificate_ssp);

    Uncompressed coordinates;
    coordinates.x.assign(subject_key.x.begin(), subject_key.x.end());
    coordinates.y.assign(subject_key.y.begin(), subject_key.y.end());
    EccPoint ecc_point = coordinates;
    v2::ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = ecc_point;
    v2::VerificationKey verification_key;
    verification_key.key = ecdsa;
    certificate.subject_attributes.push_back(verification_key);

    v2::StartAndEndValidity start_and_end;
    start_and_end.start_validity = v2::convert_time32(time_now - std::chrono::hours(1));
    start_and_end.end_validity = v2::convert_time32(time_now + std::chrono::hours(24 * config.validity_days));
    certificate.validity_restriction.push_back(start_and_end);

    if (verbose) {
        std::cout << "  Signing certificate... ";
    }

    sort(certificate);
    auto data_buffer = convert_for_signing(certificate);
    certificate.signature = backend->sign_data(sign_key.private_key, data_buffer);

    if (verbose) {
        std::cout << "OK" << std::endl;
    }

    // Generate output filename: use name if set, otherwise station_id
    std::string base_name = station.name.empty() ? station.station_id : station.name;
    std::string output_filename = base_name + ".cert";

    fs::path output_path = fs::path(config.output_dir) / output_filename;

    if (verbose) {
        std::cout << "  Writing certificate to '" << output_path.string() << "'... ";
    }

    save_certificate_to_file(output_path.string(), certificate);

    if (verbose) {
        std::cout << "OK" << std::endl;
    }

    return 0;
}

int GenerateBatchCommand::execute() {
    BatchConfig config;

    std::cout << "Parsing configuration file... ";
    if (!parse_config(config_file, config)) {
        std::cerr << "Failed to parse configuration file." << std::endl;
        return 1;
    }
    std::cout << "OK" << std::endl;

    // Validate config
    if (config.sign_key.empty() || config.sign_cert.empty() || config.output_dir.empty()) {
        std::cerr << "Error: defaults section must specify sign_key, sign_cert, and output_dir" << std::endl;
        return 1;
    }

    if (config.stations.empty()) {
        std::cerr << "Error: No stations defined in configuration file." << std::endl;
        return 1;
    }

    // Check uniqueness of station IDs and names
    {
        std::set<std::string> seen_ids;
        std::set<std::string> seen_names;
        bool has_duplicates = false;
        for (const auto& station : config.stations) {
            if (!seen_ids.insert(station.station_id).second) {
                std::cerr << "Error: Duplicate station_id '" << station.station_id << "'" << std::endl;
                has_duplicates = true;
            }
            if (!station.name.empty() && !seen_names.insert(station.name).second) {
                std::cerr << "Error: Duplicate station name '" << station.name << "'" << std::endl;
                has_duplicates = true;
            }
        }
        if (has_duplicates) {
            return 1;
        }
    }

    std::cout << "Found " << config.profiles.size() << " profile(s) and "
              << config.stations.size() << " station(s)." << std::endl;

    if (dry_run) {
        std::cout << "\n=== DRY RUN MODE ===" << std::endl;
        std::cout << "\nProfiles:" << std::endl;
        for (const auto& p : config.profiles) {
            std::cout << "  - " << p.first << std::endl;
            if (!p.second.cam_permissions.empty())
                std::cout << "    CAM: " << p.second.cam_permissions << std::endl;
            if (!p.second.denm_permissions.empty())
                std::cout << "    DENM: " << p.second.denm_permissions << std::endl;
            if (p.second.permit_vam) std::cout << "    VAM: enabled" << std::endl;
            if (p.second.permit_cpm) std::cout << "    CPM: enabled" << std::endl;
            if (p.second.permit_gn_mgmt) std::cout << "    GN-MGMT: enabled" << std::endl;
        }

        std::cout << "\nStations:" << std::endl;
        for (const auto& s : config.stations) {
            std::cout << "  - " << s.station_id;
            if (!s.name.empty()) std::cout << " (" << s.name << ")";
            std::cout << std::endl;
            std::cout << "    Subject key: " << s.subject_key << std::endl;
            if (!s.profile.empty())
                std::cout << "    Profile: " << s.profile << std::endl;
            if (s.has_inline_permissions)
                std::cout << "    Inline permissions: yes" << std::endl;
        }
        return 0;
    }

    // Create output directory if it doesn't exist
    fs::path output_dir(config.output_dir);
    if (!fs::exists(output_dir)) {
        std::cout << "Creating output directory: " << config.output_dir << std::endl;
        if (!fs::create_directories(output_dir)) {
            std::cerr << "Failed to create output directory: " << config.output_dir << std::endl;
            return 1;
        }
    }

    // Filter stations if requested
    std::vector<StationConfig> stations_to_process;
    if (!filter_stations.empty()) {
        for (const auto& station : config.stations) {
            if (std::find(filter_stations.begin(), filter_stations.end(), station.station_id) != filter_stations.end()) {
                stations_to_process.push_back(station);
            }
        }
        std::cout << "Filtering: processing " << stations_to_process.size() << " of "
                  << config.stations.size() << " stations." << std::endl;
    } else {
        stations_to_process = config.stations;
    }

    // Generate certificates
    int success_count = 0;
    int failure_count = 0;

    for (const auto& station : stations_to_process) {
        std::cout << "Generating ticket for station " << station.station_id;
        if (!station.name.empty()) {
            std::cout << " (" << station.name << ")";
        }
        std::cout << "..." << std::endl;

        int result = generate_ticket(config, station);
        if (result == 0) {
            success_count++;
            std::cout << "  ✓ Success" << std::endl;
        } else {
            failure_count++;
            std::cout << "  ✗ Failed" << std::endl;
        }
    }

    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total: " << stations_to_process.size() << " tickets" << std::endl;
    std::cout << "Success: " << success_count << std::endl;
    std::cout << "Failed: " << failure_count << std::endl;

    return (failure_count > 0) ? 1 : 0;
}

