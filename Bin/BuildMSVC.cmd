call GenerateMSVC.cmd
cd ..
cd Build

MSBuild Jinx.sln /p:Configuration=Debug && (
  echo Debug build succeeded
) || (
  echo Debug build failed
  goto ERROR
)

MSBuild Jinx.sln /p:Configuration=Release && (
  echo Release build succeeded
) || (
  echo Release build failed
  goto ERROR
)

cd ..
cd Bin
EXIT /B 0

:ERROR
cd ..
cd Bin
EXIT /B 1
