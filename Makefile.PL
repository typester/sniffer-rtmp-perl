use inc::Module::Install;
name 'Sniffer-RTMP';
all_from 'lib/Sniffer/RTMP.pm';

test_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
