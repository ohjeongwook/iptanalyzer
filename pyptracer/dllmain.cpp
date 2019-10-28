// dllmain.cpp : Defines the entry point for the DLL application.

#include <pybind11/pybind11.h>

#include "PTracerLib.h"

namespace py = pybind11;

PYBIND11_MODULE(pyptracer, m) {
    py::class_<PTracerLib>(m, "Open")
        .def("Open", &PTracerLib::Open);

    /*
    py::class_<PTracerLib>(m, "DecodeBlock")
        .def("DecodeBlock", &PTracerLib::DecodeBlock);

    py::class_<PTracerLib>(m, "DecodeInstruction")
        .def("DecodeInstruction", &PTracerLib::DecodeInstruction);*/
}