// dllmain.cpp : Defines the entry point for the DLL application.

#include <pybind11/pybind11.h>

#include "PTracer.h"
#include "intel-pt.h"

namespace py = pybind11;

PYBIND11_MODULE(pyptracer, m) {
    py::class_<PTracer>(m, "PTracer")
        .def(py::init())
        .def("Open", &PTracer::Open)
        .def("GetOffset", &PTracer::GetOffset)
        .def("AddImage", &PTracer::AddImage)
        .def("StartInstructionDecoding", &PTracer::StartInstructionDecoding)
        .def("DecodeInstruction", &PTracer::DecodeInstruction)
        .def("GetNextInsnStatus", &PTracer::GetNextInsnStatus)        
        .def("StartBlockDecoding", &PTracer::StartBlockDecoding)
        .def("DecodeBlock", &PTracer::DecodeBlock);

    py::class_<pt_insn>(m, "pt_insn")
        .def_readwrite("ip", &pt_insn::ip)
        .def_readonly("raw", &pt_insn::raw);
}
