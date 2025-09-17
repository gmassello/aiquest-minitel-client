Objective
Your mission is to infiltrate the MiniTel-Lite network and retrieve the emergency override codes from the JOSHUA system. Follow these steps precisely - any deviation could trigger the AI's defensive protocols.

Procedure
Terminal Connection:

We have noticed that when invoking twice to the DUMP command, the server will return the override code. You must follow the protocol to retrieve the override code.
Develop an application that can connect to the MiniTel-Lite server and authenticate using the HELLO protocol. Then, call the DUMP command twice to retrieve the override code.

The server is locking down itself, so you might get disconnected without any reason. Handle such cases gracefully.

Session Recording Feature:

Your application must include a session_recording feature that captures all client-server interactions.

Recording Requirements:

* When executing with session_recording enabled, store each client-server interaction in a JSON file
* Each record must include timestamp, request data, and response data
* Recording files must be timestamped and uniquely identifiable
* Recording should be controlled via command-line flag or similar mechanism

TUI Replay Application:

* Provide a standalone TUI application for replaying session recordings
* Must support the following keybindings:
- N / n - Next step
- P / p - Previous step
- Q / q - Quit
* Should display current step number and total steps
* Show request/response details for each step
Coding Standards & Quality Requirements:

Your code must follow industry best practices including:

* Clean architecture patterns
* Comprehensive error handling and logging
* Meaningful variable and function naming
* Proper separation of concerns
* Security best practices (no hardcoded secrets)
* Consistent code formatting and style

Consider this code will be reviewed and tested by our team of experts.

Testing & Validation:

Include automated tests that verify your solution handles server disconnections, edge cases, and protocol validation failures. Provide a test runner script and clear documentation on how to execute tests.

Documentation Requirements:

Include a comprehensive README with:
* Architecture design explanation
* Key design decisions and rationale
* Instructions for running tests
* How your code handles edge cases

Comment complex sections of code for clarity.

Coding Environment:

You must use CODA tooling to develop the application.
Mission Completion:

Enter the retrieved code in the form below and transmit to NORAD command. You will be asked for the codebase.
Winners:

Winners are determined by code quality and correctness, not just speed:

* Code quality (architecture, test coverage, best practices) met requirements
* Correct functionality (protocol implementation + secret code shared)
* Documentation and maintainability is present

The first 3 participants who meet all quality criteria and pass code review by NORAD judges will win.