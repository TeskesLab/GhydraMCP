package eu.starsong.ghidra.dto;

import java.util.List;

/**
 * The path a call takes from one function to another.
 *
 * <p>A call graph says who calls whom; this says how A reaches B, which is
 * the question an agent asks when it holds the two ends and wants the chain
 * between them.
 *
 * @param found   whether a path was found within the depth limit
 * @param depth   the number of hops in the path (0 when nothing was found)
 * @param maxDepth the depth limit the search ran under
 * @param from    the function the search started at
 * @param to      the function the search was looking for
 * @param path    the functions along the path, from {@code from} to {@code to}
 * @param visited how many functions the search walked through
 * @param reason  why no path was found (null when one was)
 */
public record CallPathDto(
    boolean found,
    int depth,
    int maxDepth,
    FunctionSummaryDto from,
    FunctionSummaryDto to,
    List<FunctionSummaryDto> path,
    int visited,
    String reason
) {
}
