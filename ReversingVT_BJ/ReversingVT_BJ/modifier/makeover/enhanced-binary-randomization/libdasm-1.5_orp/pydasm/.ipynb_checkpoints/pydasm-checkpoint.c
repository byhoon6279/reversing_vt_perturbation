
/*
 * pydasm -- Python module wrapping libdasm
 * (c) 2005 ero / dkbza.org
 *
*/


#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>
#include <string.h>
#include "../libdasm.h"


#define INSTRUCTION_STR_BUFFER_LENGTH   256

/*
    Instruction types borrowed from
    "libdasm.h"
*/
char *instruction_types[] = {
	"INSTRUCTION_TYPE_ASC",
	"INSTRUCTION_TYPE_DCL",
	"INSTRUCTION_TYPE_MOV",
	"INSTRUCTION_TYPE_MOVSR",
	"INSTRUCTION_TYPE_ADD",
	"INSTRUCTION_TYPE_XADD",
	"INSTRUCTION_TYPE_ADC",
	"INSTRUCTION_TYPE_SUB",
	"INSTRUCTION_TYPE_SBB",
	"INSTRUCTION_TYPE_INC",
	"INSTRUCTION_TYPE_DEC",
	"INSTRUCTION_TYPE_DIV",
	"INSTRUCTION_TYPE_IDIV",
	"INSTRUCTION_TYPE_NOT",
	"INSTRUCTION_TYPE_NEG",
	"INSTRUCTION_TYPE_STOS",
	"INSTRUCTION_TYPE_LODS",
	"INSTRUCTION_TYPE_SCAS",
	"INSTRUCTION_TYPE_MOVS",
	"INSTRUCTION_TYPE_MOVSX",
	"INSTRUCTION_TYPE_MOVZX",
	"INSTRUCTION_TYPE_CMPS",
	"INSTRUCTION_TYPE_SHX",
	"INSTRUCTION_TYPE_ROX",
	"INSTRUCTION_TYPE_MUL",
	"INSTRUCTION_TYPE_IMUL",
	"INSTRUCTION_TYPE_EIMUL",
	"INSTRUCTION_TYPE_XOR",
	"INSTRUCTION_TYPE_LEA",
	"INSTRUCTION_TYPE_XCHG",
	"INSTRUCTION_TYPE_CMP",
	"INSTRUCTION_TYPE_TEST",
	"INSTRUCTION_TYPE_PUSH",
	"INSTRUCTION_TYPE_AND",
	"INSTRUCTION_TYPE_OR",
	"INSTRUCTION_TYPE_POP",
	"INSTRUCTION_TYPE_JMP",
	"INSTRUCTION_TYPE_JMPC",
	"INSTRUCTION_TYPE_JECXZ",
	"INSTRUCTION_TYPE_SETC",
	"INSTRUCTION_TYPE_MOVC",
	"INSTRUCTION_TYPE_LOOP",
	"INSTRUCTION_TYPE_CALL",
	"INSTRUCTION_TYPE_RET",
	"INSTRUCTION_TYPE_ENTER",
	"INSTRUCTION_TYPE_INT",
	"INSTRUCTION_TYPE_BT",
	"INSTRUCTION_TYPE_BTS",
	"INSTRUCTION_TYPE_BTR",
	"INSTRUCTION_TYPE_BTC",
	"INSTRUCTION_TYPE_BSF",
	"INSTRUCTION_TYPE_BSR",
	"INSTRUCTION_TYPE_BSWAP",
	"INSTRUCTION_TYPE_SGDT",
	"INSTRUCTION_TYPE_SIDT",
	"INSTRUCTION_TYPE_SLDT",
	"INSTRUCTION_TYPE_LFP",
	"INSTRUCTION_TYPE_CLD",
	"INSTRUCTION_TYPE_STD",
	"INSTRUCTION_TYPE_XLAT",
	"INSTRUCTION_TYPE_FCMOVC",
	"INSTRUCTION_TYPE_FADD",
	"INSTRUCTION_TYPE_FADDP",
	"INSTRUCTION_TYPE_FIADD",
	"INSTRUCTION_TYPE_FSUB",
	"INSTRUCTION_TYPE_FSUBP",
	"INSTRUCTION_TYPE_FISUB",
	"INSTRUCTION_TYPE_FSUBR",
	"INSTRUCTION_TYPE_FSUBRP",
	"INSTRUCTION_TYPE_FISUBR",
	"INSTRUCTION_TYPE_FMUL",
	"INSTRUCTION_TYPE_FMULP",
	"INSTRUCTION_TYPE_FIMUL",
	"INSTRUCTION_TYPE_FDIV",
	"INSTRUCTION_TYPE_FDIVP",
	"INSTRUCTION_TYPE_FDIVR",
	"INSTRUCTION_TYPE_FDIVRP",
	"INSTRUCTION_TYPE_FIDIV",
	"INSTRUCTION_TYPE_FIDIVR",
	"INSTRUCTION_TYPE_FCOM",
	"INSTRUCTION_TYPE_FCOMP",
	"INSTRUCTION_TYPE_FCOMPP",
	"INSTRUCTION_TYPE_FCOMI",
	"INSTRUCTION_TYPE_FCOMIP",
	"INSTRUCTION_TYPE_FUCOM",
	"INSTRUCTION_TYPE_FUCOMP",
	"INSTRUCTION_TYPE_FUCOMPP",
	"INSTRUCTION_TYPE_FUCOMI",
	"INSTRUCTION_TYPE_FUCOMIP",
	"INSTRUCTION_TYPE_FST",
	"INSTRUCTION_TYPE_FSTP",
	"INSTRUCTION_TYPE_FIST",
	"INSTRUCTION_TYPE_FISTP",
	"INSTRUCTION_TYPE_FISTTP",
	"INSTRUCTION_TYPE_FLD",
	"INSTRUCTION_TYPE_FILD",
	"INSTRUCTION_TYPE_FICOM",
	"INSTRUCTION_TYPE_FICOMP",
	"INSTRUCTION_TYPE_FFREE",
	"INSTRUCTION_TYPE_FFREEP",
	"INSTRUCTION_TYPE_FXCH",
	"INSTRUCTION_TYPE_SYSENTER",
	"INSTRUCTION_TYPE_FPU_CTRL",
	"INSTRUCTION_TYPE_FPU",

	"INSTRUCTION_TYPE_MMX",

	"INSTRUCTION_TYPE_SSE",

	"INSTRUCTION_TYPE_OTHER",
	"INSTRUCTION_TYPE_PRIV",
    NULL };

/*
    Operand types borrowed from
    "libdasm.h"
*/
char *operand_types[] = {
	"OPERAND_TYPE_NONE",
	"OPERAND_TYPE_MEMORY",
	"OPERAND_TYPE_REGISTER",
	"OPERAND_TYPE_IMMEDIATE",
    NULL };

/*
    Registers borrowed from
    "libdasm.h"
*/
char *registers[] = {
    "REGISTER_EAX",
    "REGISTER_ECX",
    "REGISTER_EDX",
    "REGISTER_EBX",
    "REGISTER_ESP",
    "REGISTER_EBP",
    "REGISTER_ESI",
    "REGISTER_EDI",
    "REGISTER_NOP",
    NULL };


/*
    Register types borrowed from
    "libdasm.h"
*/
char *register_types[] = {
    "REGISTER_TYPE_GEN",
    "REGISTER_TYPE_SEGMENT",
    "REGISTER_TYPE_DEBUG",
    "REGISTER_TYPE_CONTROL",
    "REGISTER_TYPE_TEST",
    "REGISTER_TYPE_XMM",
    "REGISTER_TYPE_MMX",
    "REGISTER_TYPE_FPU",
    NULL };

// Instruction flags (prefixes)
// made using :s/^#define \([A-Z0-9a-z_]*\)[\t ]*\([0-9a-fx]*\)/{"\1",\t\t\2}/
struct flag {
  char *name;
  long value;
} flags[] = {
// Group 1
{"PREFIX_LOCK",		0x01000000},	// 0xf0
{"PREFIX_REPNE",	0x02000000},	// 0xf2
{"PREFIX_REP",		0x03000000},	// 0xf3
{"PREFIX_REPE",		0x03000000},	// 0xf3
// Group 2
{"PREFIX_ES_OVERRIDE",		0x00010000},	// 0x26
{"PREFIX_CS_OVERRIDE",		0x00020000},	// 0x2e
{"PREFIX_SS_OVERRIDE",		0x00030000},	// 0x36
{"PREFIX_DS_OVERRIDE",		0x00040000},	// 0x3e
{"PREFIX_FS_OVERRIDE",		0x00050000},	// 0x64
{"PREFIX_GS_OVERRIDE",		0x00060000},	// 0x65
// Group 3 & 4
{"PREFIX_OPERAND_SIZE_OVERRIDE",	0x00000100},	// 0x66
{"PREFIX_ADDR_SIZE_OVERRIDE",		0x00001000},	// 0x67
// Extensions
{"EXT_G1_1",		0x00000001},
{"EXT_G1_2",		0x00000002},
{"EXT_G1_3",		0x00000003},
{"EXT_G2_1",		0x00000004},
{"EXT_G2_2",		0x00000005},
{"EXT_G2_3",		0x00000006},
{"EXT_G2_4",		0x00000007},
{"EXT_G2_5",		0x00000008},
{"EXT_G2_6",		0x00000009},
{"EXT_G3_1",		0x0000000a},
{"EXT_G3_2",		0x0000000b},
{"EXT_G4",		0x0000000c},
{"EXT_G5",		0x0000000d},
{"EXT_G6",		0x0000000e},
{"EXT_G7",		0x0000000f},
{"EXT_G8",		0x00000010},
{"EXT_G9",		0x00000011},
{"EXT_GA",		0x00000012},
{"EXT_GB",		0x00000013},
{"EXT_GC",		0x00000014},
{"EXT_GD",		0x00000015},
{"EXT_GE",		0x00000016},
{"EXT_GF",		0x00000017},
{"EXT_G0",		0x00000018},
// Extra groups for 2 and 3-byte opcodes, and FPU stuff
{"EXT_T2",		0x00000020},	// opcode table 2
{"EXT_CP",		0x00000030},	// co-processor
// Instruction type flags
{"TYPE_3",		0x80000000},
// Operand flags
{"FLAGS_NONE",		0},
// Operand Addressing Methods, from the Intel manual
{"AM_A",		0x00010000},		// Direct address with segment prefix
{"AM_C",		0x00020000},		// MODRM reg field defines control register
{"AM_D",		0x00030000},		// MODRM reg field defines debug register
{"AM_E",		0x00040000},		// MODRM byte defines reg/memory address
{"AM_G",		0x00050000},		// MODRM byte defines general-purpose reg
{"AM_I",		0x00060000},		// Immediate data follows
{"AM_J",		0x00070000},		// Immediate value is relative to EIP
{"AM_M",		0x00080000},		// MODRM mod field can refer only to memory
{"AM_O",		0x00090000},		// Displacement follows (without modrm/sib)
{"AM_P",		0x000a0000},		// MODRM reg field defines MMX register
{"AM_Q",		0x000b0000},		// MODRM defines MMX register or memory 
{"AM_R",		0x000c0000},		// MODRM mod field can only refer to register
{"AM_S",		0x000d0000},		// MODRM reg field defines segment register
{"AM_T",		0x000e0000},		// MODRM reg field defines test register
{"AM_V",		0x000f0000},		// MODRM reg field defines XMM register
{"AM_W",		0x00100000},		// MODRM defines XMM register or memory 
// Extra addressing modes used in this implementation
{"AM_I1",		0x00200000},	// Immediate byte 1 encoded in instruction
{"AM_REG",		0x00210000},	// Register encoded in instruction
{"AM_IND",		0x00220000},	// Register indirect encoded in instruction
// Operand Types, from the intel manual
{"OT_a",		0x01000000},
{"OT_b",		0x02000000},	// always 1 byte
{"OT_c",		0x03000000},	// byte or word, depending on operand
{"OT_d",		0x04000000},	// double-word
{"OT_q",		0x05000000},	// quad-word
{"OT_dq",		0x06000000},	// double quad-word
{"OT_v",		0x07000000},	// word or double-word, depending on operand
{"OT_w",		0x08000000},	// always word
{"OT_p",		0x09000000},	// 32-bit or 48-bit pointer
{"OT_pi",		0x0a000000},	// quadword MMX register
{"OT_pd",		0x0b000000},	// 128-bit double-precision float
{"OT_ps",		0x0c000000},	// 128-bit single-precision float
{"OT_s",		0x0d000000},	// 6-byte pseudo descriptor
{"OT_sd",		0x0e000000},	// Scalar of 128-bit double-precision float
{"OT_ss",		0x0f000000},	// Scalar of 128-bit single-precision float
{"OT_si",		0x10000000},	// Doubleword integer register
{"OT_t",		0x11000000},	// 80-bit packed FP data
// Operand permissions
{"P_r",		0x00004000},	// Read
{"P_w",		0x00002000},	// Write
{"P_x",		0x00001000},	// Execute
// Additional operand flags
{"F_s",		0x00000100},	// sign-extend 1-byte immediate
{"F_r",		0x00000200},	// use segment register
{"F_f",		0x00000400}};	// use FPU register

//Helper macros
/* made using :'<,'>s/\(.*\)/PyObject *_\1(PyObject *self, PyObject 
 *args)\r{\r int x;\r\r    if (!PyArg_ParseTuple(args, "i", \&x))\r
 return NULL;\r\r    return PyLong_FromLong (\1(x));\r}\r/ */
PyObject *_MASK_PREFIX_G1(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_G1(x));
}

PyObject *_MASK_PREFIX_G2(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_G2(x));
}

PyObject *_MASK_PREFIX_G3(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_G3(x));
}

PyObject *_MASK_PREFIX_OPERAND(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_OPERAND(x));
}

PyObject *_MASK_PREFIX_ADDR(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PREFIX_ADDR(x));
}

PyObject *_MASK_EXT(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_EXT(x));
}

PyObject *_MASK_TYPE_FLAGS(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_TYPE_FLAGS(x));
}

PyObject *_MASK_TYPE_VALUE(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_TYPE_VALUE(x));
}

PyObject *_MASK_AM(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_AM(x));
}

PyObject *_MASK_OT(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_OT(x));
}

PyObject *_MASK_PERMS(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_PERMS(x));
}

PyObject *_MASK_FLAGS(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_FLAGS(x));
}

PyObject *_MASK_REG(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_REG(x));
}

PyObject *_MASK_MODRM_MOD(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_MODRM_MOD(x));
}

PyObject *_MASK_MODRM_REG(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_MODRM_REG(x));
}

PyObject *_MASK_MODRM_RM(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_MODRM_RM(x));
}

PyObject *_MASK_SIB_SCALE(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_SIB_SCALE(x));
}

PyObject *_MASK_SIB_INDEX(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_SIB_INDEX(x));
}

PyObject *_MASK_SIB_BASE(PyObject *self, PyObject *args)
{
    int x;

    if (!PyArg_ParseTuple(args, "i", &x))
        return NULL;

    return PyLong_FromLong(MASK_SIB_BASE(x));
}




PyObject *module;   // Main module Python object


/*
    Check whether we got a Python Object
*/
PyObject *check_object(PyObject *pObject) {
    if (!pObject) {
        PyObject *pException = PyErr_Occurred();
        if (pException) {
            PyErr_Print();  // 예외를 출력합니다.
        }
        //printf("[ERROR] Received invalid object: %p\n", pObject);  // 디버그용
        return NULL;
    }
    return pObject;
}



/*
    Assign an attribute "attr" named "name" to an object "obj"
*/
// Python 객체에 속성 설정을 위해 __dict__를 사용
// 속성 설정 후 결과 확인하는 함수
int assign_attribute(PyObject *obj, const char *name, PyObject *attr) {
    if (!attr) {
        //printf("[ERROR] Attribute '%s' creation failed\n", name);
        return -1;
    }

    if (PyObject_SetAttrString(obj, name, attr) < 0) {
        //printf("[ERROR] Failed to set attribute '%s' on object.\n", name);
        Py_DECREF(attr); // 이 부분에서 Python 예외가 발생하면 문제 발생 가능
        return -1;
    }

    if (PyErr_Occurred()) { // Python 예외가 발생했는지 확인
        PyErr_Print();
        Py_DECREF(attr);
        return -1;
    }

    Py_DECREF(attr);
    return 0;
}






/*
    Get an attribute named "attr_name" from object "obj"
    The function steals the reference! note the decrement of
    the reference count.
*/
PyObject *get_attribute(PyObject *obj, char *attr_name)
{
    PyObject *pObj;
    
    pObj = PyObject_GetAttrString(obj, attr_name);
	if(!check_object(pObj)) {
        PyErr_SetString(PyExc_ValueError, "Can't get attribute from object");
        return NULL;
    }
    
    Py_DECREF(pObj);
    return pObj;
}


/*
    Get an Long attribute named "attr_name" from object "obj" and
    return it as a "long int"
*/
long int get_long_attribute(PyObject *o, char *attr_name)
{
    PyObject *pObj;
    
    pObj = get_attribute(o, attr_name);
	if(!pObj)
        return 0;
        
    return PyLong_AsLong(pObj);;
}


/*
    Create a new class and take care of decrementing references.
*/
#include <Python.h>
#include <stdlib.h>
#include <string.h>

#include <Python.h>
#include <stdlib.h>
#include <string.h>

PyObject *create_class(const char *class_name) {
    PyTypeObject *InstructionType = (PyTypeObject *)malloc(sizeof(PyTypeObject));
    if (!InstructionType) {
        //printf("[ERROR] Memory allocation failed for %s\n", class_name);
        return NULL;
    }

    memset(InstructionType, 0, sizeof(PyTypeObject));

    // PyTypeObject 기본 필드 설정
    InstructionType->ob_base.ob_base.ob_refcnt = 1;
    InstructionType->ob_base.ob_base.ob_type = &PyType_Type;
    InstructionType->tp_name = strdup(class_name);
    InstructionType->tp_basicsize = sizeof(PyObject) + sizeof(PyObject *);
    InstructionType->tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE;
    InstructionType->tp_new = PyType_GenericNew;
    
    // ✅ __dict__ 지원을 위해 tp_dictoffset 설정
    InstructionType->tp_dictoffset = sizeof(PyObject);

    if (PyType_Ready(InstructionType) < 0) {
        //printf("[ERROR] PyType_Ready failed for class: %s\n", class_name);
        free((char *)InstructionType->tp_name);
        free(InstructionType);
        return NULL;
    }

    // ✅ Python에서 인스턴스 생성하도록 PyObject_CallObject 사용
    PyObject *pClass = PyObject_CallObject((PyObject *)InstructionType, NULL);
    if (!pClass) {
        //printf("[ERROR] Failed to create instance of class: %s\n", class_name);
        free((char *)InstructionType->tp_name);
        free(InstructionType);
        return NULL;
    }

    Py_INCREF(pClass);
    return pClass;
}



/*
    Create an "Inst" Python object from an INST structure.
*/
PyObject *create_inst_object(INST *pinst)
{
    PyObject *pPInst = create_class("Inst");
    
    if(!pPInst)
        return NULL;

    assign_attribute(pPInst, "type", PyLong_FromLong(pinst->type));
    assign_attribute(pPInst, "mnemonic", PyUnicode_FromString(pinst->mnemonic));
    assign_attribute(pPInst, "flags1", PyLong_FromLong(pinst->flags1));
    assign_attribute(pPInst, "flags2", PyLong_FromLong(pinst->flags2));
    assign_attribute(pPInst, "flags3", PyLong_FromLong(pinst->flags3));
    assign_attribute(pPInst, "modrm", PyLong_FromLong(pinst->modrm));
    assign_attribute(pPInst, "checked", PyLong_FromLong(pinst->checked));
    
    return pPInst;
}

/*
    Fill an INST structure from the data in an "Inst" Python object.
*/
void fill_inst_structure(PyObject *pPInst, PINST *_pinst)
{
    ssize_t mnemonic_length;
    PINST pinst;
    
    if(!pPInst || !_pinst)
        return;
        
    *_pinst = (PINST)calloc(1, sizeof(INST));
    pinst = *_pinst;
    if(!pinst) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return;
	}
    
    pinst->type = get_long_attribute(pPInst, "type");
    
    PyBytes_AsStringAndSize(
        get_attribute(pPInst, "mnemonic"),
        (void *)&pinst->mnemonic, &mnemonic_length);


    pinst->flags1 = get_long_attribute(pPInst, "flags1");
    pinst->flags2 = get_long_attribute(pPInst, "flags2");
    pinst->flags3 = get_long_attribute(pPInst, "flags3");
    pinst->modrm = get_long_attribute(pPInst, "modrm");
    pinst->checked = get_long_attribute(pPInst, "checked");
}


/*
    Create an "Operand" Python object from an OPERAND structure.
*/
PyObject *create_operand_object(OPERAND *op) {
    PyObject *pOperand = create_class("Operand");

    if (!pOperand) {
        //printf("[ERROR] Failed to create Operand object!\n");
        return NULL;
    }

    if (assign_attribute(pOperand, "type", PyLong_FromLong(op->type)) < 0) return NULL;
    if (assign_attribute(pOperand, "reg", PyLong_FromLong(op->reg)) < 0) return NULL;
    if (assign_attribute(pOperand, "basereg", PyLong_FromLong(op->basereg)) < 0) return NULL;
    if (assign_attribute(pOperand, "indexreg", PyLong_FromLong(op->indexreg)) < 0) return NULL;
    if (assign_attribute(pOperand, "scale", PyLong_FromLong(op->scale)) < 0) return NULL;
    if (assign_attribute(pOperand, "dispbytes", PyLong_FromLong(op->dispbytes)) < 0) return NULL;
    if (assign_attribute(pOperand, "dispoffset", PyLong_FromLong(op->dispoffset)) < 0) return NULL;
    if (assign_attribute(pOperand, "immbytes", PyLong_FromLong(op->immbytes)) < 0) return NULL;
    if (assign_attribute(pOperand, "immoffset", PyLong_FromLong(op->immoffset)) < 0) return NULL;
    if (assign_attribute(pOperand, "sectionbytes", PyLong_FromLong(op->sectionbytes)) < 0) return NULL;
    if (assign_attribute(pOperand, "section", PyLong_FromLong(op->section)) < 0) return NULL;
    if (assign_attribute(pOperand, "displacement", PyLong_FromLong(op->displacement)) < 0) return NULL;
    if (assign_attribute(pOperand, "immediate", PyLong_FromLong(op->immediate)) < 0) return NULL;
    if (assign_attribute(pOperand, "flags", PyLong_FromLong(op->flags)) < 0) return NULL;

    return pOperand;
}


/*
    Fill an OPERAND structure from the data in an "Operand" Python object.
*/
void fill_operand_structure(PyObject *pOperand, OPERAND *op)
{
    if(!pOperand || !op)
        return;
        
    op->type = get_long_attribute(pOperand, "type");
    op->reg = get_long_attribute(pOperand, "reg");
    op->basereg = get_long_attribute(pOperand, "basereg");
    op->indexreg = get_long_attribute(pOperand, "indexreg");
    op->scale = get_long_attribute(pOperand, "scale");
    op->dispbytes = get_long_attribute(pOperand, "dispbytes");
    op->dispoffset = get_long_attribute(pOperand, "dispoffset");
    op->immbytes = get_long_attribute(pOperand, "immbytes");
    op->immoffset = get_long_attribute(pOperand, "immoffset");
    op->sectionbytes = get_long_attribute(pOperand, "sectionbytes");
    op->section = get_long_attribute(pOperand, "section");
    op->displacement = get_long_attribute(pOperand, "displacement");
    op->immediate = get_long_attribute(pOperand, "immediate");
    op->flags = get_long_attribute(pOperand, "flags");
}


/*
    Create an "Instruction" Python object from an INSTRUCTION structure.
*/
PyObject *create_instruction_object(INSTRUCTION *insn) {
    PyObject *pInstruction = create_class("Instruction");  // 이제 "Instruction"만 넘김
    if (!pInstruction) {
        //printf("[ERROR] Failed to create Instruction object!\n");
        return NULL;
    }

    // __dict__ 강제 설정
    if (PyObject_SetAttrString(pInstruction, "__dict__", PyDict_New()) < 0) {
        //printf("[ERROR] Failed to initialize __dict__ for Instruction object.\n");
        Py_DECREF(pInstruction);
        return NULL;
    }

    //printf("[DEBUG] Assigning attributes to Instruction object.\n");

    // 속성 추가
    assign_attribute(pInstruction, "length", PyLong_FromLong(insn->length));
    assign_attribute(pInstruction, "type", PyLong_FromLong(insn->type));
    assign_attribute(pInstruction, "mode", PyLong_FromLong(insn->mode));
    assign_attribute(pInstruction, "opcode", PyLong_FromLong(insn->opcode));
    assign_attribute(pInstruction, "modrm", PyLong_FromLong(insn->modrm));
    assign_attribute(pInstruction, "modrm_offset", PyLong_FromLong(insn->modrm_offset));
    assign_attribute(pInstruction, "opcode_offset", PyLong_FromLong(insn->opcode_offset));
    assign_attribute(pInstruction, "sib", PyLong_FromLong(insn->sib));
    assign_attribute(pInstruction, "extindex", PyLong_FromLong(insn->extindex));
    assign_attribute(pInstruction, "fpuindex", PyLong_FromLong(insn->fpuindex));
    assign_attribute(pInstruction, "dispbytes", PyLong_FromLong(insn->dispbytes));
    assign_attribute(pInstruction, "immbytes", PyLong_FromLong(insn->immbytes));
    assign_attribute(pInstruction, "sectionbytes", PyLong_FromLong(insn->sectionbytes));
    assign_attribute(pInstruction, "flags", PyLong_FromLong(insn->flags));
    assign_attribute(pInstruction, "eflags_affected", PyLong_FromLong(insn->eflags_affected));
    assign_attribute(pInstruction, "eflags_used", PyLong_FromLong(insn->eflags_used));
    assign_attribute(pInstruction, "iop_written", PyLong_FromLong(insn->iop_written));
    assign_attribute(pInstruction, "iop_read", PyLong_FromLong(insn->iop_read));

    // 피연산자 추가
    PyObject *op1 = create_operand_object(&insn->op1);
    PyObject *op2 = create_operand_object(&insn->op2);
    PyObject *op3 = create_operand_object(&insn->op3);
    if (op1) assign_attribute(pInstruction, "op1", op1);
    if (op2) assign_attribute(pInstruction, "op2", op2);
    if (op3) assign_attribute(pInstruction, "op3", op3);
    
    // NULL 방어 코드 추가
    if (insn->ptr) {
        PyObject *ptr_obj = create_inst_object(insn->ptr);
        if (!ptr_obj) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to create ptr attribute.");
            Py_DECREF(pInstruction);
            return NULL;
        }
        assign_attribute(pInstruction, "ptr", ptr_obj);
    } else {
        assign_attribute(pInstruction, "ptr", Py_None);
        Py_INCREF(Py_None);
    }

    return pInstruction;
}




/*
    Fill an INSTRUCTION structure from the data in an "Instruction" Python object.
*/
void fill_instruction_structure(PyObject *pInstruction, INSTRUCTION *insn)
{
    insn->length = get_long_attribute(pInstruction, "length");
    insn->type = get_long_attribute(pInstruction, "type");
    insn->mode = get_long_attribute(pInstruction, "mode");
    insn->opcode = get_long_attribute(pInstruction, "opcode");
    insn->modrm = get_long_attribute(pInstruction, "modrm");
    insn->modrm_offset = get_long_attribute(pInstruction, "modrm_offset");
    insn->opcode_offset = get_long_attribute(pInstruction, "opcode_offset");
    insn->sib = get_long_attribute(pInstruction, "sib");
    insn->extindex = get_long_attribute(pInstruction, "extindex");
    insn->fpuindex = get_long_attribute(pInstruction, "fpuindex");
    insn->dispbytes = get_long_attribute(pInstruction, "dispbytes");
    insn->immbytes = get_long_attribute(pInstruction, "immbytes");
    insn->sectionbytes = get_long_attribute(pInstruction, "sectionbytes");
    insn->flags = get_long_attribute(pInstruction, "flags");
    fill_operand_structure(get_attribute(pInstruction, "op1"), &insn->op1);
    fill_operand_structure(get_attribute(pInstruction, "op2"), &insn->op2);
    fill_operand_structure(get_attribute(pInstruction, "op3"), &insn->op3);
    //fill_inst_structure(get_attribute(pInstruction, "ptr"), &insn->ptr);
    insn->iop_written = get_long_attribute(pInstruction, "iop_written");
    insn->iop_read = get_long_attribute(pInstruction, "iop_read");
    
    PyObject *pInstObj = get_attribute(pInstruction, "ptr");
    if (pInstObj && pInstObj != Py_None) {
        fill_inst_structure(pInstObj, &insn->ptr);
    } else {
        //printf("[WARNING] ptr attribute is NULL or missing!\n");
        insn->ptr = NULL;
    }
    
}

/*
    Python counterpart of libdasm's "get_instruction"
*/
#define GET_INSTRUCTION_DOCSTRING                                               \
    "Decode an instruction from the given buffer.\n\n"                          \
    "Takes in a string containing the data to disassemble and the\nmode, "      \
    "either MODE_16 or MODE_32. Returns an Instruction object or \nNone if "    \
    "the instruction can't be disassembled."
    
// PyObject *pydasm_get_instruction(PyObject *self, PyObject *args)
// {
//     PyObject *pBuffer, *pMode;
//     INSTRUCTION insn;
//     int size, mode;
//     ssize_t data_length;
//     char *data;

//     if (!args || PyObject_Length(args) != 2) {
//         PyErr_SetString(PyExc_TypeError, "Invalid number of arguments, 2 expected: (data, mode)");
//         return NULL;
//     }

//     pBuffer = PyTuple_GetItem(args, 0);
//     if (!check_object(pBuffer)) {
//         PyErr_SetString(PyExc_ValueError, "Can't get buffer from arguments");
//         return NULL;
//     }

//     pMode = PyTuple_GetItem(args, 1);
//     if (!check_object(pMode)) {
//         PyErr_SetString(PyExc_ValueError, "Can't get mode from arguments");
//         return NULL;
//     }

//     mode = PyLong_AsLong(pMode);
//     PyBytes_AsStringAndSize(pBuffer, &data, &data_length);

//     size = get_instruction(&insn, (unsigned char *)data, mode);

//     // 디버깅 메시지 추가: INSTRUCTION 구조체의 상태 확인
//     //printf("[DEBUG] get_instruction result:\n");
//     //printf("[DEBUG] length: %d\n", insn.length);
//     //printf("[DEBUG] type: %d\n", insn.type);
//     //printf("[DEBUG] mode: %d\n", insn.mode);
//     //printf("[DEBUG] opcode: 0x%x\n", insn.opcode);
//     //printf("[DEBUG] modrm: 0x%x\n", insn.modrm);
//     //printf("[DEBUG] modrm_offset: %d\n", insn.modrm_offset);
//     //printf("[DEBUG] opcode_offset: %d\n", insn.opcode_offset);
//     //printf("[DEBUG] sib: 0x%x\n", insn.sib);
//     //printf("[DEBUG] extindex: %d\n", insn.extindex);
//     //printf("[DEBUG] fpuindex: %d\n", insn.fpuindex);
//     //printf("[DEBUG] dispbytes: %d\n", insn.dispbytes);
//     //printf("[DEBUG] immbytes: %d\n", insn.immbytes);
//     //printf("[DEBUG] sectionbytes: %d\n", insn.sectionbytes);

//     if (size == 0) {
//         PyErr_SetString(PyExc_RuntimeError, "Instruction decoding failed.");
//         //printf("[ERROR] get_instruction failed. Data length: %ld, Mode: %d\n", data_length, mode);
//         return NULL; // 예외 발생 시 NULL을 반환
//     }

//     return create_instruction_object(&insn);
// }

PyObject *pydasm_get_instruction(PyObject *self, PyObject *args) {
    PyObject *pBuffer, *pMode;
    INSTRUCTION insn;
    int size, mode;
    ssize_t data_length;
    char *data;

    // 입력 인자 체크 (data, mode)
    if (!args || PyObject_Length(args) != 2) {
        PyErr_SetString(PyExc_TypeError, "Invalid number of arguments, 2 expected: (data, mode)");
        return NULL;
    }

    // 첫 번째 인자: 버퍼 (바이너리 데이터)
    pBuffer = PyTuple_GetItem(args, 0);
    if (!check_object(pBuffer)) {
        PyErr_SetString(PyExc_ValueError, "Can't get buffer from arguments");
        return NULL;
    }

    // 두 번째 인자: 모드 (MODE_16, MODE_32)
    pMode = PyTuple_GetItem(args, 1);
    if (!check_object(pMode)) {
        PyErr_SetString(PyExc_ValueError, "Can't get mode from arguments");
        return NULL;
    }

    // mode를 long으로 변환
    mode = PyLong_AsLong(pMode);

    // 버퍼 데이터를 문자열로 변환
    PyBytes_AsStringAndSize(pBuffer, &data, &data_length);

    // get_instruction 호출: 디코딩
    size = get_instruction(&insn, (unsigned char *)data, mode);

    if (size == 0) {
        // 🔥 디버깅 메시지 추가 (SSE/AVX 명령어 가능성 체크)
        fprintf(stderr, "[ERROR] Instruction decoding failed. Data length: %ld, Mode: %d, First Byte: 0x%02x\n", 
                data_length, mode, (unsigned char)data[0]);

        // ❗ SSE/AVX 명령어 프리픽스 여부 확인
        if ((unsigned char)data[0] == 0x66 || (unsigned char)data[0] == 0xF3 || (unsigned char)data[0] == 0xF2) {
            fprintf(stderr, "[WARNING] Possible SSE/AVX instruction detected. libdasm may not support this opcode.\n");
        }

        // 🔹 예외 발생 대신 `None` 반환
        Py_INCREF(Py_None);
        return Py_None;
    }

    // Instruction 객체 생성
    PyObject *instruction_obj = create_instruction_object(&insn);
    
    if (!instruction_obj) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create Instruction object.");
        return NULL;
    }

    return instruction_obj;
}



/*
    Python counterpart of libdasm's "get_instruction_string"
*/
#define GET_INSTRUCTION_STRING_DOCSTRING                                    \
    "Transform an instruction object into its string representation.\n\n"   \
    "The function takes an Instruction object; its format, either \n"       \
    "FORMAT_INTEL or FORMAT_ATT and finally an offset (refer to \n"         \
    "libdasm for meaning). Returns a string representation of the \n"       \
    "disassembled instruction."
    
PyObject *pydasm_get_instruction_string(PyObject *self, PyObject *args) {
    PyObject *pInstruction, *pFormat, *pOffset, *pStr;
    INSTRUCTION insn;
    unsigned long int offset, format;

    if (!args || PyObject_Length(args) != 3) {
        PyErr_SetString(PyExc_TypeError,
            "Invalid number of arguments, 3 expected: (instruction, format, offset)");
        return NULL;
    }

    pInstruction = PyTuple_GetItem(args, 0);
    if (!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }

    if (pInstruction == Py_None) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    memset(&insn, 0, sizeof(INSTRUCTION));
    fill_instruction_structure(pInstruction, &insn);

    pFormat = PyTuple_GetItem(args, 1);
    if (!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);

    pOffset = PyTuple_GetItem(args, 2);
    if (!check_object(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    // `data` 변수를 함수 내에서 한 번만 선언하고 초기화합니다.
    char *data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if (!data) {
        PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
        return NULL;
    }

    if (!get_instruction_string(&insn, format, offset, data, INSTRUCTION_STR_BUFFER_LENGTH)) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    pStr = PyBytes_FromStringAndSize(data, strlen(data));
    free(insn.ptr);
    free(data);

    return pStr;
}


/*
    Python counterpart of libdasm's "get_mnemonic_string"
*/
#define GET_MNEMONIC_STRING_DOCSTRING                                       \
    "Transform an instruction object's mnemonic into its string representation.\n\n"    \
    "The function takes an Instruction object and its format, either \n"    \
    "FORMAT_INTEL or FORMAT_ATT. Returns a string representation of the \n" \
    "mnemonic."
    
// pydasm_get_mnemonic_string 함수 수정
PyObject *pydasm_get_mnemonic_string(PyObject *self, PyObject *args)
{
    PyObject *pInstruction, *pFormat, *pStr;
    INSTRUCTION insn;
    unsigned long int format;

    if (!args || PyObject_Length(args) != 2) {
        PyErr_SetString(PyExc_TypeError,
            "Invalid number of arguments, 3 expected: (instruction, format)");
        return NULL;
    }

    pInstruction = PyTuple_GetItem(args, 0);
    if (!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    fill_instruction_structure(pInstruction, &insn);

    pFormat = PyTuple_GetItem(args, 1);
    if (!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);

    // `data` 변수를 함수 내에서 한 번만 선언하고 초기화합니다.
    char *data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if (!data) {
        PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
        return NULL;
    }

    get_mnemonic_string(&insn, format, data, INSTRUCTION_STR_BUFFER_LENGTH);

    pStr = PyBytes_FromStringAndSize(data, strlen(data));
    free(insn.ptr);
    free(data);

    return pStr;
}


/*
    Python counterpart of libdasm's "get_operand_string"
*/
#define GET_OPERAND_STRING_DOCSTRING                                        \
    "Transform an instruction object's operand into its string representation.\n\n"    \
    "The function takes an Instruction object; the operand index (0,1,2);\n"\
    " its format, either FORMAT_INTEL or FORMAT_ATT and finally an offset\n"\
    "(refer to libdasm for meaning). Returns a string representation of \n" \
    "the disassembled operand."
    
PyObject *pydasm_get_operand_string(PyObject *self, PyObject *args)
{
    PyObject *pInstruction, *pFormat, *pOffset, *pOpIndex, *pStr;
    INSTRUCTION insn;
    unsigned long int offset, format, op_idx;

    if (!args || PyObject_Length(args) != 4) {
        PyErr_SetString(PyExc_TypeError,
            "Invalid number of arguments, 4 expected: (instruction, operand index, format, offset)");
        return NULL;
    }

    pInstruction = PyTuple_GetItem(args, 0);
    if (!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    fill_instruction_structure(pInstruction, &insn);

    pOpIndex = PyTuple_GetItem(args, 1);
    if (!check_object(pOpIndex)) {
        PyErr_SetString(PyExc_ValueError, "Can't get operand index from arguments");
    }
    op_idx = PyLong_AsLong(pOpIndex);

    pFormat = PyTuple_GetItem(args, 2);
    if (!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);

    pOffset = PyTuple_GetItem(args, 3);
    if (!check_object(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    // `data` 변수를 함수 내에서 한 번만 선언하고 초기화합니다.
    char *data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if (!data) {
        PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
        return NULL;
    }

    if (!get_operand_string(&insn, &(insn.op1) + op_idx,
        format, offset, data, INSTRUCTION_STR_BUFFER_LENGTH)) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    pStr = PyBytes_FromStringAndSize(data, strlen(data));
    free(insn.ptr);
    free(data);

    return pStr;
}


/*
    Python counterpart of libdasm's "get_register_type"
*/
#define GET_REGISTER_TYPE_DOCSTRING                                         \
    "Get the type of the register used by the operand.\n\n"                 \
    "The function takes an Operand object and returns a Long representing\n"\
    "the type of the register."
    
PyObject *pydasm_get_register_type(PyObject *self, PyObject *args)
{
	PyObject *pOperand;
    OPERAND op;

	if(!args || PyObject_Length(args)!=1) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 1 expected: (operand)");
		return NULL;
	}
	
	pOperand = PyTuple_GetItem(args, 0);
	if(!check_object(pOperand)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&op, 0, sizeof(OPERAND));
    fill_operand_structure(pOperand, &op);
        
    return PyLong_FromLong(get_register_type(&op));
}


/*
    Map all the exported methods.
*/
static PyMethodDef pydasmMethods[] = {
	{"get_instruction", pydasm_get_instruction, METH_VARARGS,
	GET_INSTRUCTION_DOCSTRING},
	{"get_instruction_string", pydasm_get_instruction_string, METH_VARARGS,
	GET_INSTRUCTION_STRING_DOCSTRING},
	{"get_mnemonic_string", pydasm_get_mnemonic_string, METH_VARARGS,
	GET_MNEMONIC_STRING_DOCSTRING},
	{"get_operand_string", pydasm_get_operand_string, METH_VARARGS,
	GET_OPERAND_STRING_DOCSTRING},
	{"get_register_type", pydasm_get_register_type, METH_VARARGS,
	GET_REGISTER_TYPE_DOCSTRING},
//made using :'<,'>s/\(.*\)/    {"\1", _\1, METH_VARARGS, NULL},
    {"MASK_PREFIX_G1", _MASK_PREFIX_G1, METH_VARARGS, NULL},
    {"MASK_PREFIX_G1", _MASK_PREFIX_G1, METH_VARARGS, NULL},
    {"MASK_PREFIX_G2", _MASK_PREFIX_G2, METH_VARARGS, NULL},
    {"MASK_PREFIX_G3", _MASK_PREFIX_G3, METH_VARARGS, NULL},
    {"MASK_PREFIX_OPERAND", _MASK_PREFIX_OPERAND, METH_VARARGS, NULL},
    {"MASK_PREFIX_ADDR", _MASK_PREFIX_ADDR, METH_VARARGS, NULL},
    {"MASK_EXT", _MASK_EXT, METH_VARARGS, NULL},
    {"MASK_TYPE_FLAGS", _MASK_TYPE_FLAGS, METH_VARARGS, NULL},
    {"MASK_TYPE_VALUE", _MASK_TYPE_VALUE, METH_VARARGS, NULL},
    {"MASK_AM", _MASK_AM, METH_VARARGS, NULL},
    {"MASK_OT", _MASK_OT, METH_VARARGS, NULL},
    {"MASK_PERMS", _MASK_PERMS, METH_VARARGS, NULL},
    {"MASK_FLAGS", _MASK_FLAGS, METH_VARARGS, NULL},
    {"MASK_REG", _MASK_REG, METH_VARARGS, NULL},
    {"MASK_MODRM_MOD", _MASK_MODRM_MOD, METH_VARARGS, NULL},
    {"MASK_MODRM_REG", _MASK_MODRM_REG, METH_VARARGS, NULL},
    {"MASK_MODRM_RM", _MASK_MODRM_RM, METH_VARARGS, NULL},
    {"MASK_SIB_SCALE", _MASK_SIB_SCALE, METH_VARARGS, NULL},
    {"MASK_SIB_INDEX", _MASK_SIB_INDEX, METH_VARARGS, NULL},
    {"MASK_SIB_BASE", _MASK_SIB_BASE, METH_VARARGS, NULL},
	{NULL, NULL, 0, NULL}
};


/*
    Init the module, set constants.
*/

static struct PyModuleDef pydasm_module = {
    PyModuleDef_HEAD_INIT,
    "pydasm",
    NULL,
    -1,
    pydasmMethods
};

PyMODINIT_FUNC PyInit_pydasm(void) {
    int i;
    PyObject *pModule = PyModule_Create(&pydasm_module);
    if (!pModule)
        return NULL;

    // 상수 추가
    PyModule_AddIntConstant(pModule, "FORMAT_ATT", 0);
    PyModule_AddIntConstant(pModule, "FORMAT_INTEL", 1);
    PyModule_AddIntConstant(pModule, "MODE_16", 1);
    PyModule_AddIntConstant(pModule, "MODE_32", 0);

    // instruction_types, operand_types, registers, register_types 등을 추가
    for (i = 0; instruction_types[i]; i++)
        assign_attribute(pModule, instruction_types[i], PyLong_FromLong(i));
    for (i = 0; operand_types[i]; i++)
        assign_attribute(pModule, operand_types[i], PyLong_FromLong(i));
    for (i = 0; registers[i]; i++)
        assign_attribute(pModule, registers[i], PyLong_FromLong(i));
    for (i = 0; register_types[i]; i++)
        assign_attribute(pModule, register_types[i], PyLong_FromLong(i + 1));

    // flags 값을 추가
    for (size_t i = 0; i < sizeof(flags) / sizeof(struct flag); i++)
        assign_attribute(pModule, flags[i].name, PyLong_FromLong(flags[i].value));

    // Instruction 클래스를 모듈에 등록
    PyTypeObject *InstructionType = (PyTypeObject *)create_class("Instruction");
    if (InstructionType) {
        Py_INCREF(InstructionType);
        PyModule_AddObject(pModule, "Instruction", (PyObject *)InstructionType);
    } else {
        //printf("[ERROR] Failed to create Instruction class!\n");
    }

    return pModule;  // 모듈 반환
}



int main(int argc, char *argv[])
{
    wchar_t *wargv = Py_DecodeLocale(argv[0], NULL);
    Py_SetProgramName(wargv);
    PyMem_RawFree(wargv);

    Py_Initialize();
    PyInit_pydasm();

    return 0;
}