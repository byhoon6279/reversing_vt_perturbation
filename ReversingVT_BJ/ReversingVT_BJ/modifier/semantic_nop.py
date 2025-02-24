import os

def semantic_nop(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)

    # malguise 변환 실행
    os.system(f'python ./modifier/MalGuise/src/utils/pe_patcher/get_call_addr.py -f "{input_filepath}"')
    os.system(f'python ./modifier/MalGuise/src/utils/pe_patcher/patcher_custom.py -f "{input_filepath}"')

    # 불필요한 파일 삭제
    os.system(f'rm -rf "{input_filepath}.i64"')
    os.system(f'rm -rf "{input_filepath}.txt"')

    # 변환된 파일명을 저장 경로에 맞게 설정
    output_filename = sample.replace('.exe', '_semantic_nop.exe')
    output_filepath = os.path.join(save_dir, output_filename)

    # 변환된 파일을 opath에 저장
    os.system(f'mv "{input_filepath.replace(".exe", "_semantic_nop.exe")}" "{output_filepath}"')

    print(f"semantic_nop 변환 완료: {output_filepath}")
