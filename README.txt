dlinsert - Insert LC_LOAD_DYLIB commands into existing binaries
--------------------------------------------------------------------------------

This program is a fork of Tylio's "insert_dylib". I am in the process of
cleaning up and simplifying the code. Improvements so far include:

  - migration from Xcode to CMake for building;
  - huge improvements to the usage message content and formatting; and
  - better user-facing messages, warnings, and errors.

My goals moving forward are to continue to add comments to the code and extract
chunks of code into functions to reduce repeated or messy code.

For more information, see the original project:

<https://github.com/Tyilo/insert_dylib>
