#include <nlohmann/json.hpp>
#include <argparse/argparse.hpp>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[]) {
    argparse::ArgumentParser program("json_parser");

    program.add_argument("-f", "--file")
        .help("Path to the JSON file")
        .required();

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    std::string file_path = program.get<std::string>("--file");

    try {
        // Read the JSON file
        std::ifstream json_file(file_path);
        if (!json_file.is_open()) {
            throw std::runtime_error("Could not open file: " + file_path);
        }

        nlohmann::json json_data;
        json_file >> json_data;

        // Print the parsed JSON data
        std::cout << "Parsed JSON data:" << std::endl;
        std::cout << json_data.dump(4) << std::endl; // Pretty print with indentation

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
