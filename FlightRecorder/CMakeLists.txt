# CMakeList.txt : CMake project for FlightRecorder, include source and define
# project specific logic here.
#

add_library(flight_recorder STATIC "FlightRecorder.cpp" "FlightRecorder.h")
target_include_directories(flight_recorder PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(FlightRecorder "main.cpp")
target_link_libraries(FlightRecorder PRIVATE flight_recorder)

if(BUILD_TESTING)
  add_executable(FlightRecorderTests "flight_recorder_tests.cpp")
  target_link_libraries(FlightRecorderTests PRIVATE flight_recorder)
  add_test(NAME FlightRecorderTests COMMAND FlightRecorderTests)
endif()

set_property(TARGET flight_recorder FlightRecorder PROPERTY CXX_STANDARD 20)
if(BUILD_TESTING)
  set_property(TARGET FlightRecorderTests PROPERTY CXX_STANDARD 20)
endif()
