cmake_minimum_required(VERSION 3.12)
project(virtual-tagger-plugin)

find_package(Cutter REQUIRED)
find_package(Rizin REQUIRED)

set(CUTTER_INSTALL_PLUGDIR "${Cutter_USER_PLUGINDIR}" CACHE STRING "Directory to install Cutter plugin into")

set(CMAKE_AUTOMOC ON)

add_library(virtual_tagger_plugin MODULE
    VirtualTaggerPlugin.h
    VirtualTaggerPlugin.cpp)

target_link_libraries(virtual_tagger_plugin PRIVATE Cutter::Cutter Rizin::Core)
install(TARGETS virtual_tagger_plugin DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
