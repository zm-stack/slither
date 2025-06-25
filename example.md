Traceback (most recent call last):
  File "/home/ziming/.local/bin/slither", line 8, in <module>
    sys.exit(main())
  File "/home/ziming/.local/lib/python3.10/site-packages/slither/__main__.py", line 776, in main
    main_impl(all_detector_classes=detectors, all_printer_classes=printers)
  File "/home/ziming/.local/lib/python3.10/site-packages/slither/__main__.py", line 882, in main_impl
    ) = process_all(filename, args, detector_classes, printer_classes)
  File "/home/ziming/.local/lib/python3.10/site-packages/slither/__main__.py", line 96, in process_all
    compilations = compile_all(target, **vars(args))
  File "/home/ziming/.local/lib/python3.10/site-packages/crytic_compile/crytic_compile.py", line 749, in compile_all
    raise ValueError(f"{str(target)} is not a file or directory.")
ValueError: example.sol is not a file or directory.
