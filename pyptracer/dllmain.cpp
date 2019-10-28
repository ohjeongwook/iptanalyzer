// dllmain.cpp : Defines the entry point for the DLL application.

#include <pybind11/pybind11.h>

#include "PTracerLib.h"

namespace py = pybind11;

PYBIND11_MODULE(pyptracer, m) {
    py::class_<PTracerLib>(m, "PTracerLib")
        .def(py::init())
        .def("Open", &PTracerLib::Open)
        .def("StartInstructionTrace", &PTracerLib::StartInstructionTrace)
        .def("DecodeInstruction", &PTracerLib::DecodeInstruction)
        .def("StartBlockTracing", &PTracerLib::StartBlockTracing)
        .def("DecodeBlock", &PTracerLib::DecodeBlock);
}
