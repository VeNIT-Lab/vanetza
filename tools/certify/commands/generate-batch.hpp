#ifndef CERTIFY_COMMANDS_GENERATE_BATCH_HPP
#define CERTIFY_COMMANDS_GENERATE_BATCH_HPP

#include "command.hpp"
#include <map>
#include <string>
#include <vector>

struct PermissionProfile {
    std::string cam_permissions;
    std::string denm_permissions;
    bool permit_vam = false;
    bool permit_cpm = false;
    bool permit_gn_mgmt = false;
};

struct StationConfig {
    std::string station_id;
    std::string name;
    std::string subject_key;
    std::string profile;  // reference to named profile
    // inline permission overrides (optional)
    std::string cam_permissions;
    std::string denm_permissions;
    bool permit_vam = false;
    bool permit_cpm = false;
    bool permit_gn_mgmt = false;
    bool has_inline_permissions = false;
};

struct BatchConfig {
    std::string sign_key;
    std::string sign_cert;
    std::string output_dir;
    int validity_days = 7;
    std::map<std::string, PermissionProfile> profiles;
    std::vector<StationConfig> stations;
};

class GenerateBatchCommand : public Command
{
public:
    bool parse(const std::vector<std::string>&) override;
    int execute() override;

private:
    std::string config_file;
    bool dry_run = false;
    bool verbose = false;
    std::vector<std::string> filter_stations;

    bool parse_config(const std::string& filename, BatchConfig& config);
    int generate_ticket(const BatchConfig& config, const StationConfig& station);
};

#endif /* CERTIFY_COMMANDS_GENERATE_BATCH_HPP */

