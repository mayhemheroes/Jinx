/*
The Jinx library is distributed under the MIT License (MIT)
https://opensource.org/licenses/MIT
See LICENSE.TXT or Jinx.h for license details.
Copyright (c) 2016 James Boer
*/

#include "UnitTest.h"

using namespace Jinx;


TEST_CASE("Test Syntax and Parsing Errors", "[Errors]")
{
	SECTION("Test number parsing error error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 34.56.78
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test unassigned variable error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3 + x
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test mismatched quote error")
	{
		static const char * scriptText =
			u8R"(
    
			a is "Invalid string
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operators #1 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3 + - 4
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operators #2 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is (3 +) - 4
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operands #1 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3 4

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operands #2 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3 (4)

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operands #3 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is (((3)) 4)

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operands #4 error")
	{
		static const char * scriptText =
			u8R"(
			
			function return f
				return 23
			end
    
			a is 3 f

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too many operands #5 error")
	{
		static const char * scriptText =
			u8R"(
			
			function return f
				return 23
			end
    
			a is 3(f)

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too few operands #1 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3 +

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test too few operands #2 error")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3 * (4 / )

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test function declaration scope error")
	{
		static const char * scriptText =
			u8R"(
    
			begin
				function somefunction
				end
			end
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test function declaration execution frame error")
	{
		static const char * scriptText =
			u8R"(
    
			function somefunction
				function someotherfunction
				end
			end
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test function declaration duplicate error")
	{
		static const char * scriptText =
			u8R"(
    
			function somefunction
			end

			function somefunction
			end
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test multi-script function declaration duplicate error")
	{
		static const char * scriptText1 =
			u8R"(
    
			private function return collisiontest
				return 123
			end

			a is collisiontest

			)";

		static const char * scriptText2 =
			u8R"(
    
			private function return collisiontest
				return 456
			end

			a is collisiontest

			)";

		auto runtime = TestCreateRuntime();
		auto script1 = TestCreateScript(scriptText1, runtime);
		auto script2 = TestCreateScript(scriptText2, runtime);
		REQUIRE(script1);
		REQUIRE(!script2);
	}

	SECTION("Test function declaration keyword match error")
	{
		static const char * scriptText =
			u8R"(
    
			function while
			end
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test library property scope error #1")
	{
		static const char * scriptText1 =
			u8R"(
    
			library test

			private x is 5
			
			)";

		static const char * scriptText2 =
			u8R"(
    
			import test
     
			b is x		

			)";

		auto runtime = TestCreateRuntime();
		auto script1 = TestExecuteScript(scriptText1, runtime);
		auto script2 = TestExecuteScript(scriptText2, runtime);
		REQUIRE(script1);
		REQUIRE(!script2);
	}

	SECTION("Test library property scope error #2")
	{
		static const char * scriptText1 =
			u8R"(
    
			library test

			private x is 5
			
			)";

		static const char * scriptText2 =
			u8R"(
    
			import test
     
			b is test x		

			)";

		auto runtime = TestCreateRuntime();
		auto script1 = TestExecuteScript(scriptText1, runtime);
		auto script2 = TestExecuteScript(scriptText2, runtime);
		REQUIRE(script1);
		REQUIRE(!script2);
	}

	SECTION("Test duplicate property error #1")
	{
		static const char * scriptText =
			u8R"(
			
			import test

			private a is 123
			public a is 345
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test duplicate property error #2")
	{
		static const char * scriptText =
			u8R"(
			
			import test

			private a a is 123
			public a a is 345
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test property readonly attribute")
	{
		static const char * scriptText =
			u8R"(
    
			readonly private a is 123
			a is 456
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test property readonly attribute #1")
	{
		static const char * scriptText1 =
			u8R"(
    
			library test

			readonly public prop is 333

			)";

		static const char * scriptText2 =
			u8R"(
    
			import test
     
			prop is 12345

			)";

		auto runtime1 = TestCreateRuntime();
		auto scriptBytecode1 = runtime1->Compile(scriptText1);
		REQUIRE(scriptBytecode1);

		auto runtime2 = TestCreateRuntime();
		auto script1 = runtime2->CreateScript(scriptBytecode1);
		script1->Execute();
		auto script2 = TestExecuteScript(scriptText2, runtime2);
		REQUIRE(script1);
		REQUIRE(!script2);
	}

	SECTION("Test property readonly attribute #2")
	{
		static const char * scriptText1 =
			u8R"(
    
			library test

			readonly public prop is 333

			)";

		static const char * scriptText2 =
			u8R"(
    
			import test
     
			decrement prop

			)";

		auto runtime1 = TestCreateRuntime();
		auto scriptBytecode1 = runtime1->Compile(scriptText1);
		REQUIRE(scriptBytecode1);

		auto runtime2 = TestCreateRuntime();
		auto script1 = runtime2->CreateScript(scriptBytecode1);
		script1->Execute();
		auto script2 = TestExecuteScript(scriptText2, runtime2);
		REQUIRE(script1);
		REQUIRE(!script2);
	}

	SECTION("Test collection initialization list error #1")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3, 2, 1,
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test collection initialization list error #2")
	{
		static const char * scriptText =
			u8R"(
    
			a is 3, 2 1
			
			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test collection initialization list of key-value pairs error #1")
	{
		static const char * scriptText =
			u8R"(
    
			-- Missing bracket
			a is [1, "red"], [2, "green", [3, "blue"]

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test collection initialization list of key-value pairs error #2")
	{
		static const char * scriptText =
			u8R"(
    
			-- Missing key
			a is [1, "red"], [2, "green"], ["blue"]

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test collection initialization list of key-value pairs error #3")
	{
		static const char * scriptText =
			u8R"(
    
			-- Missing comma
			a is [1, "red"], [2, "green"] [3, "blue"]

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test missing return valid in function error #1")
	{
		static const char * scriptText =
			u8R"(
    
			function return somefunc
			end

			a is somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}
	
	SECTION("Test missing return valid in function error #2")
	{
		static const char * scriptText =
			u8R"(
    
			function return somefunc
				if true
				else
					return "some string"
				end
			end

			a is somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}
	
	SECTION("Test missing return valid in function error #3")
	{
		static const char * scriptText =
			u8R"(
    
			function return somefunc
				if false
					return "some string"
				else
				end
			end

			a is somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test missing return valid in function error #4")
	{
		static const char * scriptText =
			u8R"(
    
			function return somefunc
				if false
					return "some string"
				else
					return
				end
				return "some string"
			end

			a is somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test missing return valid in function error #5")
	{
		static const char * scriptText =
			u8R"(
    
			function return somefunc
				if false
					return "some string"
				else if false
					return "some string"
				else if false
				else 
					return "some string"
				end
			end

			a is somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test no return validation")
	{
		static const char * scriptText =
			u8R"(
    
			function somefunc
				return "some string"
			end

			somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test no return function assignment")
	{
		static const char * scriptText =
			u8R"(
    
			function somefunc
			end

			a is somefunc

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test external variable with variable name collision")
	{
		const char * scriptText =
			u8R"(
			
			some var is 345
			external some var
			another var is some var

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test external variable with property name collision")
	{
		const char * scriptText =
			u8R"(
			
			private some var is 345
			external some var
			another var is some var

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

	SECTION("Test external variable scope")
	{
		const char * scriptText =
			u8R"(
			
			begin
				external some var
			end

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}


	SECTION("Test external variable frame")
	{
		const char * scriptText =
			u8R"(
			
			function something
				external some var
			end

			)";

		auto script = TestCreateScript(scriptText);
		REQUIRE(!script);
	}

}