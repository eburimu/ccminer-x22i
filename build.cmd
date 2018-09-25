REM COMMAND LINE MS BUILD

REM Note: /m:2 = 2 threads, but for host code only...


"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\msbuild" ccminer.vcxproj /m /p:Configuration=Release /p:Platform=x64



