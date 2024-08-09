read me

perturbation : 구현된 3가지 perturbation의 소스코드 가 저장된 폴더
sample : input, output 바이너리가 저장될 폴더

input_dir : working_dir/sample/input_sample
output_dir : working_dir/sample/perturbated_sample/perturbation_name(resource_change/instruction_change/adding_nop)

* working_dir/sample/section_move/ : adding_nop을 위해 .text 섹션이 복사된 샘플들이 저장됩니다. (adding_nop의 input dir이 됩니다.) 

1. change resource
	input_dir의 바이너리들을 input으로 받아 본 섹션 대상으로 perturbation을 수행합니다.
	perturbation이 적용된 바이너리들은 output_dir에 저장됩니다.

2. change instruction
	input_dir의 바이너리들을 input으로 받아 본 섹션 대상으로 perturbation을 수행합니다.
	perturbation이 적용된 바이너리들은 output_dir에 저장됩니다.

3. adding nop
	section_move.py 가 선행 되어야합니다.
	python seciton_move.py input_dir
	section_move.py는 32bit 바이너리만 지원합니다.
	input_dir의 바이너리들 중 32bit 바이너리만 input으로 받아 .text, .code 섹션을 바이너리의 맨 마지막 부분으로 복사합니다.
	복사된 새로운 섹션의 이름을 .text로 변경한뒤 working_dir/sample/section_move/ 에 저장됩니다.

	섹션이 옯겨진 바이너리가 저장된 working_dir/sample/section_move/ 의 바이너리를 input 으로 받아 perturbation을 수행합니다.
	perturbation이 적용된 바이너리들은 output_dir에 저장됩니다.