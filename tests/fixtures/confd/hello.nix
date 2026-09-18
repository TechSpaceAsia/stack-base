# Fixture for the conf.d mechanism (tests/test_template.py and tests/vm.nix):
# a project-wide module that leaves one observable mark on every node.
{ ... }:
{
  environment.etc."stackbase-confd-marker".text = "hello from conf.d\n";
}
