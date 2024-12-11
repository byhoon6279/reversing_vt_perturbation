import matplotlib
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
matplotlib.use('Agg')  # GUI 백엔드 비활성화

# # 데이터 정의
# labels = ['mdb', 'ldb', 'ndb', 'hsb', 'cbc', 'hdb']
# sizes = [800, 232, 27, 12, 2, 2]
# colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0', '#ffb3e6']

# # 파이 차트 그리기 (라벨 제거)
# fig, ax = plt.subplots(figsize=(12, 10))
# ax.pie(
#     sizes,
#     labels=None,  # 라벨 제거
#     startangle=140,
#     colors=colors
# )

# # 표 데이터 준비
# table_data = [[f"  {label}", f"{size} ({size / sum(sizes) * 100:.1f}%)"] for label, size in zip(labels, sizes)]

# # 표 추가
# table = plt.table(
#     cellText=table_data,
#     colLabels=["Signature Type", "Count (Proportion)"],
#     loc='bottom',
#     cellLoc='center',
#     colColours=["#f2f2f2", "#f2f2f2"],
#     colWidths=[0.2, 0.2]
# )

# # 각 셀의 색상 지정 (Signature Type 열에 색 추가)
# for i, color in enumerate(colors):
#     table[(i + 1, 0)].set_facecolor(color)  # 첫 번째 열 (Signature Type)에 색상 추가

# # 셀 높이 및 너비 조정
# table.scale(3, 2)  # 가로는 그대로, 세로 높이는 2배로 늘림

# # 폰트 크기 조정
# table.auto_set_font_size(False)
# table.set_fontsize(10)

# # 레이아웃 조정
# #plt.subplots_adjust(left=0.2, bottom=0.4)  # 표가 잘리지 않도록 조정
# plt.subplots_adjust(left=0.05, bottom=0.25, top=0.9, right=0.95)  # 여백 최소화

# # # 그래프를 고해상도로 파일로 저장
# plt.savefig('sigtype.pdf', format='pdf', dpi=600)
# plt.close()

#----------------------------------------------------------------------------------------
# 유니코드 지원 폰트 설정
plt.rcParams["font.family"] = "DejaVu Sans"  # 시스템에 설치된 유니코드 지원 폰트

# # 데이터 준비
# sections = [
#     '.text', '.data', '.rdata', '.rsrc', 'upx1', '.fdata', '.g', 'code', '.reloc', '.coni',
#     '.not_found_section', '.edata', '.\`\\x13\\x1c\\x02', '.code', 'uxaq', '', '.idata',
#     '\\x05\\x12\\\\\\x18', '.ddata', '.data\\x00\\x18"', '.piano', 'pihx', 'u2a\\x18', '.bhgj', 'чw\\x1cr'
# ]

# counts = [
#     332, 298, 103, 26, 9, 4, 4, 3, 3, 2,
#     2, 1, 1, 1, 1, 1, 1,
#     1, 1, 1, 1, 1, 1, 1, 1
# ]

# # 데이터 정렬 (내림차순)
# sorted_indices = np.argsort(counts)[::-1]
# sections_sorted = np.array(sections)[sorted_indices]
# counts_sorted = np.array(counts)[sorted_indices]

# # 막대 차트 그리기
# fig, ax = plt.subplots(figsize=(10, 8))
# ax.barh(sections_sorted, counts_sorted, color='skyblue')

# # 시각적 꾸미기
# ax.set_xlabel("Frequency", fontsize=12)
# ax.set_ylabel("Sections", fontsize=12)
# ax.set_title("Section Hash Distribution", fontsize=14, weight='bold')
# ax.invert_yaxis()  # 큰 값이 위로 오도록 반전
# ax.grid(axis='x', linestyle='--', alpha=0.7)

# # 주석 추가
# for i, v in enumerate(counts_sorted):
#     ax.text(v + 1, i, str(v), fontsize=10, va='center')

# # 그래프 보여주기
# plt.tight_layout()
# plt.savefig('section_hash_distribution_fixed.pdf', format='pdf', dpi=600)
# plt.close()
#----------------------------------------------------------------------------------------
# 데이터 준비
# sections = ['.text', '.data', '.rsrc', '.rdata', '.overlay', '.not_found', '.g', '.reloc', 'n2', 'upx1', 
#             '.edata', '.jdata', 'code', '.data2', '7h_', 'd2', 'r2', '.itext', '.c2', '.not_found_section', 
#             '.textf1', '.code', '.cod', '.e4', '.t2', '.idata', '.z', 'data', '.round', '.d...']
# counts = [320, 281, 253, 188, 24, 16, 16, 12, 10, 7, 7, 5, 5, 5, 5, 4, 4, 4, 4, 3, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1]

# # 데이터 정렬
# sorted_indices = np.argsort(counts)[::-1]
# sections_sorted = np.array(sections)[sorted_indices]
# counts_sorted = np.array(counts)[sorted_indices]

# # 그래프 생성
# fig, ax = plt.subplots(figsize=(10, 8))
# ax.barh(sections_sorted, counts_sorted, color='skyblue')

# # 꾸미기
# ax.set_xlabel("Frequency", fontsize=12)
# ax.set_ylabel("Sections", fontsize=12)
# ax.set_title("Hex Code Distribution by Sections", fontsize=14, weight='bold')
# ax.invert_yaxis()  # 큰 값이 위로 오도록 반전
# ax.grid(axis='x', linestyle='--', alpha=0.7)

# # 빈도수 레이블 추가
# for i, v in enumerate(counts_sorted):
#     ax.text(v + 1, i, str(v), fontsize=10, va='center')

# # 저장 또는 표시
# plt.tight_layout()
# plt.savefig('hex_code_distribution.pdf', format='pdf', dpi=600)
# plt.close()

#----------------------------------------------------------------------------------------
# 데이터 정의
# sections = ['.text', '.data', '.rdata', '.rsrc', '.overlay', '.g', 'upx1', '.not_found', '.reloc', 'n2',
#             'code', '.edata', '.not_found_section', '.jdata', '.data2', '7݇h_', '.fdata', 'd2', 'r2', 
#             '.itext', '.c2', '.code', '.coni', '.idata', '.textf1', '.cod', '.e4', '.t2', '.`\\x13\\x1c\\x02', 
#             'uxaq', '', '\\x05\\x12\\\\\\x18', '.ddata', '.data\\x00\\x18"', '.piano', 'pihx', 'u2a\\x18', 
#             '.bhgj', 'чw\\x1cr', '.z', 'data', '.round', '.d...']
# counts = [652, 579, 291, 279, 24, 20, 16, 16, 15, 10, 8, 8, 5, 5, 5, 5, 4, 4, 4, 4, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

# # 데이터 정렬 (내림차순)
# sorted_indices = np.argsort(counts)[::-1]
# sections_sorted = np.array(sections)[sorted_indices]
# counts_sorted = np.array(counts)[sorted_indices]

# # 수평 막대 그래프 생성
# fig, ax = plt.subplots(figsize=(12, 10))
# y_pos = np.arange(len(sections_sorted))
# ax.barh(y_pos, counts_sorted, color='skyblue', edgecolor='black')

# # 축 레이블 및 제목 설정
# ax.set_yticks(y_pos)
# ax.set_yticklabels(sections_sorted, fontsize=8)
# ax.set_xlabel('Count of Sub-Signatures', fontsize=12)
# ax.set_ylabel('Sections', fontsize=12)
# ax.set_title('Distribution of Sub-Signatures Across Sections', fontsize=14, weight='bold')
# ax.invert_yaxis()  # 큰 값이 위로 오도록 반전

# # 데이터 값 표시
# for i, v in enumerate(counts_sorted):
#     ax.text(v + 5, i, str(v), fontsize=8, va='center')

# # 레이아웃 조정 및 표시
# plt.tight_layout()

# plt.savefig("sub_signature_section_distribution_piechart.pdf", format="pdf", dpi=300)
# plt.close()
#----------------------------------------------------------------------------------------
# Data preparation
labels = [
    '.text', '.data', '.rdata', '.rsrc', '.reloc', 'code', '.edata', '.jdata',
    '.data2', '.fdata', '.itext', '.code', '.idata', '.textf1', '.ddata', 'data'
]
types = [
    'Code Section', 'Data Section', 'Data Section', 'Data Section', 'Data Section',
    'Code Section', 'Data Section', 'Data Section', 'Code Section', 'Data Section',
    'Data Section', 'Code Section', 'Data Section', 'Code Section', 'Data Section', 'Data Section'
]

# Count sections by type
type_counts = {'Code Section': 0, 'Data Section': 0}
for t in types:
    type_counts[t] += 1

# Pie chart data
section_labels = list(type_counts.keys())
section_sizes = list(type_counts.values())
colors = ['#ff9999', '#66b3ff']

# Plot pie chart
fig, ax = plt.subplots(figsize=(8, 6))
ax.pie(section_sizes, labels=section_labels, autopct='%1.1f%%', startangle=140, colors=colors)
plt.title("Proportion of Code and Data Sections", fontsize=14, weight='bold')

# Show chart
plt.tight_layout()
plt.savefig("section_ratio.pdf", format="pdf", dpi=300)
plt.close()