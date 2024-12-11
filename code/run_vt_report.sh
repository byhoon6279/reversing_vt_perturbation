#!/bin/bash

cd /home/younghoon.ban/reversing_vt/Clamav_analysis/working_dir/code || exit 1

API_KEYS=(
    'ac3b05e11b4f2545fc806868bb59f2543f26f3c66d021d7bc4cb697228fd5b55'  # naver 
    'f7d55da77fce83f5851cbea25d8c0a0b1089c1afd53d55a856b0255b54791c12'  # kakao
    '6f1d52c9a1932e250b6b26615e050504ce16232021e625b8c015203c6db87c35'  # google
    '2732d0d5012bf3d61d8f7e8060fdd3319ec6d784c3138e9ec3b7c10f95999458'  # ssu

)

for API_KEY in "${API_KEYS[@]}"; do
    echo "Using API key: $API_KEY"
    python3 vt_report_script.py "$API_KEY"  # API 키를 파라미터로 전달하여 파이썬 코드 실행

    # 파이썬 프로그램이 종료되었을 때 500개 요청이 완료되었거나 할당량 초과가 발생한 경우
    echo "Completed requests with API key: $API_KEY"
done

echo "All API keys have been used."