package eu.starsong.ghidra.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

/**
 * The two ways an address is written, and the way a pair is chosen.
 *
 * <p>Both halves of this test use the strings the code really produces, not
 * strings made up for it:
 * <ul>
 *   <li>the Ghidra side is {@code Address.toString()}, which pads the offset to
 *       the width of the address space and prefixes the space name when the
 *       space shows it: "00401000" for a 32-bit default space,
 *       "0000000000401000" for a 64-bit one, "ram:00401000" for a space that
 *       shows its name;</li>
 *   <li>the BSim side is what {@code BSimQueryService.describeNote} builds:
 *       {@code "0x" + Long.toHexString(address)}, which is "0x401000";</li>
 *   <li>a match is the map {@code describeNote} produces, with the keys
 *       "function", "address", "executable", "path", "similarity" and
 *       "significance".</li>
 * </ul>
 *
 * <p>Comparing the two sides as text said an unchanged function had moved,
 * because "00401000" and "0x401000" are not the same string. The comparison
 * is over the numbers now, and the cases below are that comparison.
 */
public class BSimDiffServiceTest {

    /** The Ghidra spelling of the entry point of a 32-bit function. */
    private static final String GHIDRA_32 = "00401000";

    /** The Ghidra spelling of the entry point of a 64-bit function. */
    private static final String GHIDRA_64 = "0000000000401000";

    /** The BSim spelling of the same address. */
    private static final String BSIM = "0x401000";

    @Test
    public void the_two_spellings_of_one_address_are_one_address() {
        assertTrue(BSimDiffService.sameAddress(GHIDRA_32, BSIM));
        assertTrue(BSimDiffService.sameAddress(BSIM, GHIDRA_32));
    }

    @Test
    public void a_64_bit_address_is_the_same_address_as_its_short_form() {
        assertTrue(BSimDiffService.sameAddress(GHIDRA_64, BSIM));
        assertTrue(BSimDiffService.sameAddress(BSIM, GHIDRA_64));
    }

    @Test
    public void an_address_space_prefix_does_not_change_the_address() {
        assertTrue(BSimDiffService.sameAddress("ram:" + GHIDRA_32, BSIM));
    }

    @Test
    public void the_padding_of_the_address_space_does_not_change_the_address() {
        assertTrue(BSimDiffService.sameAddress("401000", BSIM));
        assertTrue(BSimDiffService.sameAddress("0x00401000", BSIM));
    }

    @Test
    public void a_different_address_is_not_the_same_address() {
        assertFalse(BSimDiffService.sameAddress(GHIDRA_32, "0x402000"));
        assertFalse(BSimDiffService.sameAddress(GHIDRA_32, "00401010"));
    }

    @Test
    public void an_address_that_is_not_a_number_is_not_parsed() {
        assertNull(BSimDiffService.parseAddress("not-an-address"));
        assertNull(BSimDiffService.parseAddress(null));
        assertNull(BSimDiffService.parseAddress(""));
        assertNull(BSimDiffService.parseAddress("0x"));
    }

    @Test
    public void an_address_that_cannot_be_parsed_falls_back_to_the_text() {
        // Nothing was parsed, so nothing is claimed: the text is compared.
        assertTrue(BSimDiffService.sameAddress("not-an-address", "not-an-address"));
        assertFalse(BSimDiffService.sameAddress(GHIDRA_32, "not-an-address"));
    }

    @Test
    public void the_pair_is_the_most_similar_match_of_the_executable() {
        Map<String, Object> best = BSimDiffService.bestPair(
            matches(), "cmd.exe");
        assertNotNull(best);
        assertEquals("main", best.get("function"));
        assertEquals(Double.valueOf(0.91), best.get("similarity"));
    }

    @Test
    public void a_match_of_another_executable_is_never_the_pair() {
        // "other.exe" is not the executable that was asked for, so the match
        // of the most similar function of the corpus is not the pair.
        Map<String, Object> best = BSimDiffService.bestPair(
            matches(), "cmd.exe");
        assertNotNull(best);
        assertEquals("cmd.exe", best.get("executable"));
    }

    @Test
    public void a_match_of_no_known_executable_means_no_pair() {
        assertNull(BSimDiffService.bestPair(matches(), "missing.exe"));
    }

    @Test
    public void the_executable_of_a_match_is_compared_case_insensitively() {
        Map<String, Object> best = BSimDiffService.bestPair(
            matches(), "CMD.EXE");
        assertNotNull(best);
        assertEquals("main", best.get("function"));
    }

    @Test
    public void no_matches_means_no_pair() {
        Map<String, Object> queried = new LinkedHashMap<>();
        queried.put("matches", new ArrayList<>());
        assertNull(BSimDiffService.bestPair(queried, "cmd.exe"));
    }

    @Test
    public void an_answer_without_matches_means_no_pair() {
        assertNull(BSimDiffService.bestPair(new LinkedHashMap<>(), "cmd.exe"));
    }

    /**
     * The matches a BSim answer holds, in the shape the answer builds them.
     *
     * <p>The addresses are the BSim spelling, the executables are the names the
     * database recorded, and the similarities are the ones BSim reported.
     */
    private static List<Map<String, Object>> matches() {
        List<Map<String, Object>> matches = new ArrayList<>();
        matches.add(match("helper", "0x401100", "other.exe", 0.99));
        matches.add(match("main", "0x401000", "cmd.exe", 0.91));
        matches.add(match("start", "0x401200", "cmd.exe", 0.72));
        return matches;
    }

    private static Map<String, Object> match(String function, String address,
            String executable, double similarity) {
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("function", function);
        match.put("address", address);
        match.put("executable", executable);
        match.put("path", "/src");
        match.put("similarity", Double.valueOf(similarity));
        match.put("significance", Double.valueOf(0.5));
        return match;
    }
}
