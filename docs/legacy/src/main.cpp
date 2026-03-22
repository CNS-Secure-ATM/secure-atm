#include <nlohmann/json.hpp>
#include <argparse/argparse.hpp>
#include <iostream>
#include <fstream>

using json = nlohmann::json;
using namespace std;

int main(int argc, char* argv[]) {
    argparse::ArgumentParser program("json_parser");

    program.add_argument("-f", "--file")
        .help("Path to the JSON file")
        .required();

    try {
        program.parse_args(argc, argv);
    } catch (const runtime_error& err) {
        cerr << err.what() << endl;
        cerr << program;
        return 1;
    }

    string file_path = program.get<string>("--file");

    try {
        // Read the JSON file
        ifstream f(file_path);
        if (!f.is_open()) {
            throw runtime_error("Could not open file: " + file_path);
        }

        json data;
        f >> data;

        // Print the parsed JSON data
        cout << "Parsed JSON data:" << endl;
        cout << data.dump(4) << endl; // Pretty print with indentation

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
