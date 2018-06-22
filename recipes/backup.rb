#
# Cookbook Name:: percona
# Recipe:: backup
#

node.normal["percona"]["backup"]["configure"] = true

include_recipe "percona::package_repo"

case node["platform_family"]
when "debian"
  package "xtrabackup" do
    options "--force-yes"
  end
when "rhel"
  package "percona-xtrabackup" unless node['percona']['version'] == '5.7'
  package "percona-xtrabackup-24" if node['percona']['version'] == '5.7'
end

# access grants
include_recipe "percona::access_grants" unless node["percona"]["skip_passwords"]
