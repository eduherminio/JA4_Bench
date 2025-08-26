﻿using BenchmarkDotNet.Running;
using System.Reflection;

#if DEBUG
using BenchmarkDotNet.Configs;
#endif

#if DEBUG
BenchmarkSwitcher.FromAssembly(Assembly.GetExecutingAssembly()).Run(args, new DebugInProcessConfig());
#else
BenchmarkSwitcher.FromAssembly(Assembly.GetExecutingAssembly()).Run(args);
#endif
