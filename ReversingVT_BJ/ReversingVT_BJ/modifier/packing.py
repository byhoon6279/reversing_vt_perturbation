import subprocess
import random
from colorama import Fore,Style

def PrintRed(text):
    return (Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def pack_with_upx(input_path: str, output_path:str) -> bool:
    print(PrintRed("If you want to packing this binary, Please run only this option in Windows!!!!!"))
    print(PrintRed("** Other options must be run on Linux to work properly."))
    try:
        subprocess.run(['upx', input_path, "-"+str(random.randrange(1,9)) ,'-o',output_path], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f'Error packing {input_path}: {e}')
        return False

if __name__ == "__main__":
    input_exe_path = "putty.exe" 
    output_exe_path = input_exe_path.replace('.', '_modified.')
    pack_with_upx(input_exe_path, output_exe_path)
