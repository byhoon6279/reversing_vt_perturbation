# Perturbation Automation Scripts

This project contains two scripts to apply binary perturbation techniques to PE `.exe` files:

- `RQ1_modifier.py`: Applies all 14 perturbation techniques sequentially to each file.
- `RQ2_modifier.py`: Applies all combinations of 2 to 14 perturbation techniques to each file.

---

## 🧪 How to Use

### 🔹 1. RQ1_modifier.py – 단일 perturbation 일괄 적용

**모든 `.exe` 파일에 대해 14가지 perturbation 기법을 순차 적용**합니다.  
하위 디렉토리까지 재귀 탐색하며, 멀티프로세싱 지원.

#### ✅ 실행 명령

```bash
python RQ1_modifier.py -i <input_dir> -o <output_dir> [--multi] [-j <num_jobs>]
```

#### 🔧 인자 설명

| 옵션               | 설명                                                                 |
|--------------------|----------------------------------------------------------------------|
| `-i`, `--input`    | 입력 디렉토리 (`.exe` 포함, 하위 디렉토리도 재귀 탐색)              |
| `-o`, `--output`   | 출력 디렉토리                                                        |
| `--multi`          | 멀티프로세싱 활성화                                                  |
| `-j`, `--jobs`     | 멀티프로세싱 시 사용할 프로세스 수 (기본: CPU 절반)                  |

#### 📌 예시

```bash
python RQ1_modifier.py -i ./dataset -o ./m_samples
python RQ1_modifier.py -i ./dataset -o ./m_samples --multi -j 8
```

---

### 🔹 2. RQ2_modifier.py – perturbation 조합 전수 적용

**2~14개 perturbation 기법의 모든 조합을 각 파일에 적용**합니다.  
각 조합은 별도 디렉토리에 저장되며, 멀티프로세싱과 임시 디렉토리 자동 정리 기능 포함.

#### ✅ 실행 명령

```bash
python RQ2_modifier.py -i <input_dir> -o <output_dir> [-l <log_file>] [--cleanup] [-j <num_jobs>]
```

#### 🔧 인자 설명

| 옵션               | 설명                                                                 |
|--------------------|----------------------------------------------------------------------|
| `-i`, `--input`    | 입력 디렉토리 (하위 디렉토리 포함 탐색)                             |
| `-o`, `--output`   | 출력 디렉토리 (없으면 자동 생성)                                     |
| `-l`, `--log`      | 로그 파일 경로 (기본: `debug_output.txt`)                           |
| `--cleanup`        | 실행 후 임시 디렉토리 자동 삭제 (`tmp/perturbation_tmp/`)            |
| `-j`, `--jobs`     | 멀티프로세싱 프로세스 수 (기본: CPU 절반)                            |

#### 📌 예시

```bash
python RQ2_modifier.py -i ~/Dike_lable/label_test/ -o ~/Dike_lable/RQ2
python RQ2_modifier.py -i ./dataset -o ./perturbed_out -j 12 --cleanup
```

---

## 🗂 출력 구조 예시

```
output/
├── 2_perts/
│   └── familyA/
│       └── sample.exe|MDH_EDS.exe
├── 3_perts/
│   └── ...
...
├── 14_perts/
```

- `2_perts`, `3_perts`, ..., `14_perts` 는 perturbation 개수에 따라 분리됨
- 입력 디렉토리 구조를 그대로 유지하여 저장됨

---

## 🧰 perturbation 기법 목록 (공통)

```text
modify_dos_header, extend_dos_stub, coff_header, rich_header, optional_header,
section_rename, section_add, section_append, content_shifting,
jmp_overlay_back, overlay_append, instruction_change, resource_change, section_increase
```

---

## 🧼 임시 디렉토리 관리

- 경로: `<input 상위>/tmp/perturbation_tmp/`
- `RQ2_modifier.py`는 기존 `tmp` 디렉토리 제거 후 새로 생성
- `--cleanup` 옵션을 주면 실행 완료 후 자동 삭제됨