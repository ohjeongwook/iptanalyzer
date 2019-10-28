// dllmain.cpp : Defines the entry point for the DLL application.

#include <pybind11/pybind11.h>

#include "PTracer.h"

namespace py = pybind11;

PYBIND11_MODULE(pyptracer, m) {
    py::class_<PTracer>(m, "PTracer")
        .def(py::init())
        .def("Open", &PTracer::Open)
        .def("StartInstructionTrace", &PTracer::StartInstructionTrace)
        .def("DecodeInstruction", &PTracer::DecodeInstruction)
        .def("StartBlockTracing", &PTracer::StartBlockTracing)
        .def("DecodeBlock", &PTracer::DecodeBlock);
}
