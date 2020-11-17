#include <idc.idc>
static main()
{
  // turn on coagulation of data in the final pass of analysis
  SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) | AF2_DODATA);
  Message("Waiting for the end of the auto analysis...\n");
  Wait();
  Message("\n\n------ Creating the output file.... --------\n");
  auto file = GetIdbPath()[0:-4] + ".gdl";
  GenCallGdl(file, file, CHART_GEN_GDL|CHART_PRINT_NAMES);      // create the assembler file
  Message("All done, exiting...\n");
  Exit(0);              // exit to OS, error code 0 - success
}
