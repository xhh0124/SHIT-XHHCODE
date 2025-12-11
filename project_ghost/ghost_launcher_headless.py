#!/usr/bin/env python2
import os
import sys
import readline
import datetime
import shutil

readline.set_completer_delims(" \t\n=")
readline.parse_and_bind("tab: complete")


def main1():

    # print_logo()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = "./ghidra/support/analyzeHeadless"

    if not os.path.isfile(dir_path + "/ghost.py"):
        print("Please copy ghost.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + "/ghidra_analysis_options_prescript.py"):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)

    while True:
        program_to_analyze_directory = "./sample/190/190_bads02"
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory += "/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print(program_to_analyze_directory)
            print("Invalid path. please enter a valid path.")
            sys.exit(1)

    for program in os.listdir(program_to_analyze_directory):
        try:
            programpath = os.path.join(program_to_analyze_directory, program)
            outputpath = os.path.join(program_to_analyze_directory, f"{program}_output")
            if os.path.isdir(programpath) or os.path.exists(outputpath):
                continue
            output_directory = program_to_analyze_directory + program + "_output"
            os.makedirs(output_directory)
        except Exception as e:
            print("Output directory alread exists!")
            output_directory = datetime.datetime.now().strftime("%H:%M:%S") + program + "_output"

        os.environ["OUTPUT_DIRECTORY"] = output_directory
        os.environ["PROGRAM_NAME"] = program
        cmd = "sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(
            ghidra_path,
            program_to_analyze_directory,
            program_to_analyze_directory + "/" + program,
            dir_path + "/ghidra_analysis_options_prescript.py",
            dir_path + "/ghost.py",
        )

        print(cmd)
        os.system(cmd)


def main2():

    # print_logo()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = "./ghidra/support/analyzeHeadless"

    if not os.path.isfile(dir_path + "/ghost.py"):
        print("Please copy ghost.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + "/ghidra_analysis_options_prescript.py"):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)

    while True:
        program_to_analyze_directory = "./sample/190/190_goods02"
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory += "/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)

    for program in os.listdir(program_to_analyze_directory):
        try:
            programpath = os.path.join(program_to_analyze_directory, program)
            outputpath = os.path.join(program_to_analyze_directory, f"{program}_output")
            if os.path.isdir(programpath) or os.path.exists(outputpath):
                continue
            output_directory = program_to_analyze_directory + program + "_output"
            os.makedirs(output_directory)
        except Exception as e:
            print("Output directory alread exists!")
            output_directory = datetime.datetime.now().strftime("%H:%M:%S") + program + "_output"

        os.environ["OUTPUT_DIRECTORY"] = output_directory
        os.environ["PROGRAM_NAME"] = program
        cmd = "sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(
            ghidra_path,
            program_to_analyze_directory,
            program_to_analyze_directory + "/" + program,
            dir_path + "/ghidra_analysis_options_prescript.py",
            dir_path + "/ghost.py",
        )

        print(cmd)
        os.system(cmd)


def main3():

    # print_logo()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = "./ghidra/support/analyzeHeadless"

    if not os.path.isfile(dir_path + "/ghost.py"):
        print("Please copy ghost.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + "/ghidra_analysis_options_prescript.py"):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)

    while True:
        program_to_analyze_directory = "./sample/CWE190_bad"
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory += "/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)

    for program in os.listdir(program_to_analyze_directory):
        try:
            programpath = os.path.join(program_to_analyze_directory, program)
            outputpath = os.path.join(program_to_analyze_directory, f"{program}_output")
            if os.path.isdir(programpath) or os.path.exists(outputpath):
                continue
            output_directory = program_to_analyze_directory + program + "_output"
            os.makedirs(output_directory)
        except Exception as e:
            print("Output directory alread exists!")
            output_directory = datetime.datetime.now().strftime("%H:%M:%S") + program + "_output"

        os.environ["OUTPUT_DIRECTORY"] = output_directory
        os.environ["PROGRAM_NAME"] = program
        cmd = "sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(
            ghidra_path,
            program_to_analyze_directory,
            program_to_analyze_directory + "/" + program,
            dir_path + "/ghidra_analysis_options_prescript.py",
            dir_path + "/ghost.py",
        )

        print(cmd)
        os.system(cmd)


def main4():

    # print_logo()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = "./ghidra/support/analyzeHeadless"

    if not os.path.isfile(dir_path + "/ghost.py"):
        print("Please copy ghost.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + "/ghidra_analysis_options_prescript.py"):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)

    while True:
        program_to_analyze_directory = "./sample/CWE190_good"
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory += "/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)

    for program in os.listdir(program_to_analyze_directory):
        try:
            programpath = os.path.join(program_to_analyze_directory, program)
            outputpath = os.path.join(program_to_analyze_directory, f"{program}_output")
            if os.path.isdir(programpath) or os.path.exists(outputpath):
                continue
            output_directory = program_to_analyze_directory + program + "_output"
            os.makedirs(output_directory)
        except Exception as e:
            print("Output directory alread exists!")
            output_directory = datetime.datetime.now().strftime("%H:%M:%S") + program + "_output"

        os.environ["OUTPUT_DIRECTORY"] = output_directory
        os.environ["PROGRAM_NAME"] = program
        cmd = "sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(
            ghidra_path,
            program_to_analyze_directory,
            program_to_analyze_directory + "/" + program,
            dir_path + "/ghidra_analysis_options_prescript.py",
            dir_path + "/ghost.py",
        )

        print(cmd)
        os.system(cmd)


if __name__ == "__main__":
    main1()
    main2()
   # main3()
   # main4()
