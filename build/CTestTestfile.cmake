# CMake generated Testfile for 
# Source directory: /home/hungqt/res
# Build directory: /home/hungqt/res/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(AllTests "/home/hungqt/res/build/unit_tests")
set_tests_properties(AllTests PROPERTIES  _BACKTRACE_TRIPLES "/home/hungqt/res/CMakeLists.txt;57;add_test;/home/hungqt/res/CMakeLists.txt;0;")
add_test(StatsEngineTests "/home/hungqt/res/build/test_stats_engine")
set_tests_properties(StatsEngineTests PROPERTIES  _BACKTRACE_TRIPLES "/home/hungqt/res/CMakeLists.txt;63;add_test;/home/hungqt/res/CMakeLists.txt;0;")
add_test(BehaviorTrackerTests "/home/hungqt/res/build/test_behavior_tracker")
set_tests_properties(BehaviorTrackerTests PROPERTIES  _BACKTRACE_TRIPLES "/home/hungqt/res/CMakeLists.txt;68;add_test;/home/hungqt/res/CMakeLists.txt;0;")
add_test(FirewallActionTests "/home/hungqt/res/build/test_firewall_action")
set_tests_properties(FirewallActionTests PROPERTIES  _BACKTRACE_TRIPLES "/home/hungqt/res/CMakeLists.txt;73;add_test;/home/hungqt/res/CMakeLists.txt;0;")
subdirs("_deps/googletest-build")
