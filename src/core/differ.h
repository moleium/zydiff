#pragma once

#include "logger.h"
#include "parser.h"
#include "analyzer.h"
#include <string>
#include <vector>
#include <memory>

class BinaryDiffer {
public:
  struct DiffResult {
    std::vector<std::pair<FunctionAnalyzer::Function, FunctionAnalyzer::Function>> matched_functions;
    std::vector<FunctionAnalyzer::Function> unmatched_primary;
    std::vector<FunctionAnalyzer::Function> unmatched_secondary;
  };

  BinaryDiffer(const std::string& primary_path, const std::string& secondary_path);

  auto Compare() -> DiffResult;

private:
  auto CalculateFunctionSimilarity(
      const FunctionAnalyzer::Function& f1,
      const FunctionAnalyzer::Function& f2,
      std::vector<std::string>& diff_details) -> double;
      
  auto MatchFunctions(
      const std::vector<FunctionAnalyzer::Function>& primary_funcs,
      const std::vector<FunctionAnalyzer::Function>& secondary_funcs) 
      -> std::vector<std::pair<FunctionAnalyzer::Function, FunctionAnalyzer::Function>>;

  auto GetInstructionDifferences(
      const std::vector<std::string>& seq1,
      const std::vector<std::string>& seq2)
      -> std::pair<std::vector<std::string>, std::vector<std::string>>;

  auto GetLCS(
      const std::vector<std::string>& seq1,
      const std::vector<std::string>& seq2)
      -> std::vector<std::string>;

  std::unique_ptr<BinaryParser> primary_;
  std::unique_ptr<BinaryParser> secondary_;
}; 