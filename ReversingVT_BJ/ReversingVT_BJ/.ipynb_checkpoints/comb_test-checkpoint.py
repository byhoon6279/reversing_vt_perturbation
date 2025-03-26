import itertools

perts = [
    "modify_dos_header", "extend_dos_stub", "coff_header", "rich_header",
    "optional_header", "section_rename", "section_add", "section_append",
    "content_shifting", "jmp_overlay_back", "overlay_append", "instruction_change",
    "resource_change", "section_increase"
]

# 🔥 2개 ~ 14개 조합 생성
all_combinations = {i: list(itertools.combinations(perts, i)) for i in range(2, 15)}

# ✅ 확인
for num, combos in all_combinations.items():
    print(f"🔹 {num}개 조합 ({len(combos)}개):", combos[:3], "...")
