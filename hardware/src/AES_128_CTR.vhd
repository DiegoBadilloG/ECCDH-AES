library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;
use ieee.math_real.all;

entity AES_128_CTR is
    generic(
        d_width: integer := 64
    );
    Port ( 
        clk: in std_logic;
        
        key: in std_logic_vector (127 downto 0);
        recived_encrypted: in std_logic_vector (127 downto 0); 
        is_recived: in std_logic;
        sended_encrypted: out std_logic_vector (127 downto 0)
    );
end AES_128_CTR;

architecture Behavioral of AES_128_CTR is
    type sbox_array is array (0 to 255) of STD_LOGIC_VECTOR(7 downto 0);
    constant sbox_rom : sbox_array := (
        x"63", x"7C", x"77", x"7B", x"F2", x"6B", x"6F", x"C5", x"30", x"01", x"67", x"2B", x"FE", x"D7", x"AB", x"76",
        x"CA", x"82", x"C9", x"7D", x"FA", x"59", x"47", x"F0", x"AD", x"D4", x"A2", x"AF", x"9C", x"A4", x"72", x"C0",
        x"B7", x"FD", x"93", x"26", x"36", x"3F", x"F7", x"CC", x"34", x"A5", x"E5", x"F1", x"71", x"D8", x"31", x"15",
        x"04", x"C7", x"23", x"C3", x"18", x"96", x"05", x"9A", x"07", x"12", x"80", x"E2", x"EB", x"27", x"B2", x"75",
        x"09", x"83", x"2C", x"1A", x"1B", x"6E", x"5A", x"A0", x"52", x"3B", x"D6", x"B3", x"29", x"E3", x"2F", x"84",
        x"53", x"D1", x"00", x"ED", x"20", x"FC", x"B1", x"5B", x"6A", x"CB", x"BE", x"39", x"4A", x"4C", x"58", x"CF",
        x"D0", x"EF", x"AA", x"FB", x"43", x"4D", x"33", x"85", x"45", x"F9", x"02", x"7F", x"50", x"3C", x"9F", x"A8",
        x"51", x"A3", x"40", x"8F", x"92", x"9D", x"38", x"F5", x"BC", x"B6", x"DA", x"21", x"10", x"FF", x"F3", x"D2",
        x"CD", x"0C", x"13", x"EC", x"5F", x"97", x"44", x"17", x"C4", x"A7", x"7E", x"3D", x"64", x"5D", x"19", x"73",
        x"60", x"81", x"4F", x"DC", x"22", x"2A", x"90", x"88", x"46", x"EE", x"B8", x"14", x"DE", x"5E", x"0B", x"DB",
        x"E0", x"32", x"3A", x"0A", x"49", x"06", x"24", x"5C", x"C2", x"D3", x"AC", x"62", x"91", x"95", x"E4", x"79",
        x"E7", x"C8", x"37", x"6D", x"8D", x"D5", x"4E", x"A9", x"6C", x"56", x"F4", x"EA", x"65", x"7A", x"AE", x"08",
        x"BA", x"78", x"25", x"2E", x"1C", x"A6", x"B4", x"C6", x"E8", x"DD", x"74", x"1F", x"4B", x"BD", x"8B", x"8A",
        x"70", x"3E", x"B5", x"66", x"48", x"03", x"F6", x"0E", x"61", x"35", x"57", x"B9", x"86", x"C1", x"1D", x"9E",
        x"E1", x"F8", x"98", x"11", x"69", x"D9", x"8E", x"94", x"9B", x"1E", x"87", x"E9", x"CE", x"55", x"28", x"DF",
        x"8C", x"A1", x"89", x"0D", x"BF", x"E6", x"42", x"68", x"41", x"99", x"2D", x"0F", x"B0", x"54", x"BB", x"16"
    );
    constant inv_sbox_rom : sbox_array := (
       x"52", x"09", x"6a", x"d5", x"30", x"36", x"a5", x"38", x"bf", x"40", x"a3", x"9e", x"81", x"f3", x"d7", x"fb", 
       x"7c", x"e3", x"39", x"82", x"9b", x"2f", x"ff", x"87", x"34", x"8e", x"43", x"44", x"c4", x"de", x"e9", x"cb", 
       x"54", x"7b", x"94", x"32", x"a6", x"c2", x"23", x"3d", x"ee", x"4c", x"95", x"0b", x"42", x"fa", x"c3", x"4e", 
       x"08", x"2e", x"a1", x"66", x"28", x"d9", x"24", x"b2", x"76", x"5b", x"a2", x"49", x"6d", x"8b", x"d1", x"25", 
       x"72", x"f8", x"f6", x"64", x"86", x"68", x"98", x"16", x"d4", x"a4", x"5c", x"cc", x"5d", x"65", x"b6", x"92", 
       x"6c", x"70", x"48", x"50", x"fd", x"ed", x"b9", x"da", x"5e", x"15", x"46", x"57", x"a7", x"8d", x"9d", x"84", 
       x"90", x"d8", x"ab", x"00", x"8c", x"bc", x"d3", x"0a", x"f7", x"e4", x"58", x"05", x"b8", x"b3", x"45", x"06", 
       x"d0", x"2c", x"1e", x"8f", x"ca", x"3f", x"0f", x"02", x"c1", x"af", x"bd", x"03", x"01", x"13", x"8a", x"6b",
       x"3a", x"91", x"11", x"41", x"4f", x"67", x"dc", x"ea", x"97", x"f2", x"cf", x"ce", x"f0", x"b4", x"e6", x"73", 
       x"96", x"ac", x"74", x"22", x"e7", x"ad", x"35", x"85", x"e2", x"f9", x"37", x"e8", x"1c", x"75", x"df", x"6e", 
       x"47", x"f1", x"1a", x"71", x"1d", x"29", x"c5", x"89", x"6f", x"b7", x"62", x"0e", x"aa", x"18", x"be", x"1b", 
       x"fc", x"56", x"3e", x"4b", x"c6", x"d2", x"79", x"20", x"9a", x"db", x"c0", x"fe", x"78", x"cd", x"5a", x"f4", 
       x"1f", x"dd", x"a8", x"33", x"88", x"07", x"c7", x"31", x"b1", x"12", x"10", x"59", x"27", x"80", x"ec", x"5f", 
       x"60", x"51", x"7f", x"a9", x"19", x"b5", x"4a", x"0d", x"2d", x"e5", x"7a", x"9f", x"93", x"c9", x"9c", x"ef",
       x"a0", x"e0", x"3b", x"4d", x"ae", x"2a", x"f5", x"b0", x"c8", x"eb", x"bb", x"3c", x"83", x"53", x"99", x"61", 
       x"17", x"2b", x"04", x"7e", x"ba", x"77", x"d6", x"26", x"e1", x"69", x"14", x"63", x"55", x"21", x"0c", x"7d"
    );
    type rcon_array is array (0 to 10) of STD_LOGIC_VECTOR(7 downto 0);
    constant r_con : rcon_array := (
        x"00", x"01", x"02", x"04", x"08", x"10", x"20", x"40", x"80", x"1b", x"36"
    );
    
    signal waiting_next: std_logic := '1';
    signal has_encrypted: std_logic := '0';
    signal to_decrypt: std_logic_vector (127 downto 0);
    
    ---------------------------------------
    --      TESTING VARIABLES
    ---------------------------------------
    signal testing_plaintext: std_logic_vector (127 downto 0) := x"6bc1bee22e409f96e93d7e117393172a"; 
    signal testing_encrypted : std_logic_vector (127 downto 0); 
    signal testing_decrypted : std_logic_vector (127 downto 0);     
    signal testing_key:  std_logic_vector (127 downto 0) := x"2b7e151628aed2a6abf7158809cf4f3c";
    signal testing_nonce:  std_logic_vector (127 downto 0) := x"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    
 --funciones para AES 128 modo CTR
    function subBytes ( input_state : std_logic_vector(127 downto 0)) return std_logic_vector is
        variable result_state : std_logic_vector(127 downto 0);
    begin
        for i in 0 to 15 loop
            result_state(i*8 + 7 downto i*8) := sbox_rom(to_integer(unsigned(input_state(i*8 + 7 downto i*8))));
        end loop;
        return result_state;
    end function subBytes;
    
    function subBytes_32b ( input_state : std_logic_vector(31 downto 0)) return std_logic_vector is
        variable result_state : std_logic_vector(31 downto 0);
    begin
        for i in 0 to 3 loop
            result_state(i*8 + 7 downto i*8) := sbox_rom(to_integer(unsigned(input_state(i*8 + 7 downto i*8))));
        end loop;
        return result_state;
    end function subBytes_32b;
   
    
    function ShiftRows (state : std_logic_vector(127 downto 0)) return std_logic_vector is
        variable result : std_logic_vector(127 downto 0);
    begin
        result(7 downto 0) := state(7 downto 0);
        result(15 downto 8) := state(47 downto 40);
        result(23 downto 16) := state(87 downto 80);
        result(31 downto 24) := state(127 downto 120);
        
        result(39 downto 32) := state(39 downto 32);
        result(47 downto 40) := state(79 downto 72);
        result(55 downto 48) := state(119 downto 112);
        result(63 downto 56) := state(31 downto 24);
        
        result(71 downto 64) := state(71 downto 64);
        result(79 downto 72) := state(111 downto 104);
        result(87 downto 80) := state(23 downto 16);
        result(95 downto 88) := state(63 downto 56);
        
        result(103 downto 96) := state(103 downto 96);
        result(111 downto 104) := state(15 downto 8);
        result(119 downto 112) := state(55 downto 48);
        result(127 downto 120) := state(95 downto 88);

        return result;
    end function;
    
    function gMul (a_val : std_logic_vector(7 downto 0); b_val : std_logic_vector(7 downto 0)) return std_logic_vector is
        variable p : std_logic_vector(7 downto 0) := (others => '0');
        variable a_temp : std_logic_vector(7 downto 0);
        variable b_temp : std_logic_vector(7 downto 0);
        variable counter : integer;
    begin
        a_temp := a_val;
        b_temp := b_val;
        
        for counter in 0 to 7 loop
            if b_temp(0) = '1' then
                p := p xor a_temp;
            end if;
            
            if a_temp(7) = '1' then
                a_temp := std_logic_vector(unsigned(a_temp) sll 1);
                a_temp(0) := '0'; 
                a_temp := a_temp xor "00011011";
            else
                a_temp := std_logic_vector(unsigned(a_temp) sll 1);
            end if;
            
            b_temp := std_logic_vector(unsigned(b_temp) srl 1);
        end loop;
        
        return p;
    end function gMul;
    
    function mix_column ( input_column : std_logic_vector(31 downto 0)) return std_logic_vector is
        variable r : std_logic_vector(31 downto 0);
    begin
        r(7 downto 0)     := gMul(input_column(7 downto 0), x"02") xor gMul(input_column(31 downto 24), x"01") xor gMul(input_column(23 downto 16),x"01") xor gMul(input_column(15 downto 8), x"03");
        r(15 downto 8)    := gMul(input_column(15 downto 8), x"02") xor gMul(input_column(7 downto 0), x"01") xor gMul(input_column(31 downto 24), x"01") xor gMul(input_column(23 downto 16), x"03");
        r(23 downto 16)   := gMul(input_column(23 downto 16), x"02") xor gMul(input_column(15 downto 8), x"01") xor gMul(input_column(7 downto 0), x"01") xor gMul(input_column(31 downto 24), x"03");
        r(31 downto 24)   := gMul(input_column(31 downto 24), x"02") xor gMul(input_column(23 downto 16), x"01") xor gMul(input_column(15 downto 8), x"01") xor gMul(input_column(7 downto 0), x"03");
        
        return r;
    end function mix_column;
    
    function MixColumns (input_state : std_logic_vector(127 downto 0)) return std_logic_vector is
        variable state : std_logic_vector(127 downto 0);
        variable col : std_logic_vector(31 downto 0);
        variable col_mixed : std_logic_vector(31 downto 0);
    begin
        state := input_state;
        for i in 0 to 3 loop
            col := state(i*32 + 31 downto i*32);
            col_mixed := mix_column(col);
            state(i*32 + 31 downto i*32) := col_mixed;
        end loop;
        return state;
    end function MixColumns;
    
    function rotWord (input_word : std_logic_vector(31 downto 0)) return std_logic_vector is
        variable rotated_word : std_logic_vector(31 downto 0);
    begin
        rotated_word(31 downto 24) := input_word(7 downto 0);
        rotated_word(23 downto 16) := input_word(31 downto 24);
        rotated_word(15 downto 8)  := input_word(23 downto 16);
        rotated_word(7 downto 0)   := input_word(15 downto 8);
        
        return rotated_word;
    end function rotWord;
    
    function keyExpansion (key : std_logic_vector(127 downto 0)) return std_logic_vector is
        variable expanded_key : std_logic_vector(1407 downto 0);
        variable temp_word : std_logic_vector(31 downto 0);
    begin
        for i in 0 to 3 loop
            expanded_key(i*32 + 31 downto i*32) := key(i*32 + 31 downto i*32);
        end loop;

        for i in 4 to 43 loop
            temp_word := expanded_key((i-1)*32 + 31 downto (i-1)*32);
            if i mod 4 = 0 then
                temp_word := rotWord(temp_word);
                temp_word := subBytes_32b(temp_word);
                temp_word(7 downto 0) := ((temp_word(7 downto 0)) xor (r_con(i/4)));
            end if;
                expanded_key(i*32 + 31 downto i*32) := (expanded_key((i-4)*32 + 31 downto (i-4)*32)) xor (temp_word);
        end loop;

        return expanded_key;
    end function keyExpansion;
    
    function addRoundKey_128b ( state : std_logic_vector(127 downto 0);key : std_logic_vector(127 downto 0)) return std_logic_vector is
        variable result : std_logic_vector(127 downto 0);
    begin
        result := state xor key;
        return result;
    end function addRoundKey_128b;
    
    function addRoundKey_192b (state : std_logic_vector(191 downto 0); key : std_logic_vector(127 downto 0)) return std_logic_vector is
        variable result : std_logic_vector(127 downto 0);
    begin
        result := state(127 downto 0) xor key;
        return result;
    end function addRoundKey_192b;
    
    function encrypt_block (counter_block: std_logic_vector(191 downto 0); key: std_logic_vector (127 downto 0)) return std_logic_vector is
        variable result: std_logic_vector (127 downto 0);
        variable exp_key: std_logic_vector (1407 downto 0);
        variable state1: std_logic_vector (127 downto 0);
    begin
        exp_key := keyExpansion(key);
        state1 := addRoundKey_192b(counter_block, exp_key(127 downto 0));
        for i in 1 to 9 loop
            state1 := subBytes(state1);
            state1 := shiftRows(state1);
            state1 := MixColumns(state1);
            state1 := addRoundKey_128b(state1, exp_key((i*128) + 127 downto i*128));
        end loop;
        state1 := subBytes(state1);
        state1 := shiftRows(state1);
        result  := addRoundKey_128b(state1, exp_key(1407 downto 1280));

        return result;
    end function encrypt_block;
    
    
    function shift_encript(encrypt: std_logic_vector (127 downto 0)) return std_logic_vector is 
        variable result: std_logic_vector (127 downto 0);
    begin
        result(7 downto 0) := encrypt(127 downto 120);
        result(15 downto 8) := encrypt(119 downto 112);
        result(23 downto 16) := encrypt(111 downto 104);
        result(31 downto 24) := encrypt(103 downto 96);
        
        result(39 downto 32) := encrypt(95 downto 88);
        result(47 downto 40) := encrypt(87 downto 80);
        result(55 downto 48) := encrypt(79 downto 72);
        result(63 downto 56) := encrypt(71 downto 64);
        
        result(71 downto 64) := encrypt(63 downto 56);
        result(79 downto 72) := encrypt(55 downto 48);
        result(87 downto 80) := encrypt(47 downto 40);
        result(95 downto 88) :=  encrypt(39 downto 32);
        
        result(103 downto 96) := encrypt(31 downto 24);
        result(111 downto 104) := encrypt(23 downto 16);
        result(119 downto 112) := encrypt(15 downto 8);
        result(127 downto 120) := encrypt(7 downto 0);
        
        return result;
    end function shift_encript;
    
    function encrypt_ctr(plaintext, key, nonce: std_logic_vector (127 downto 0)) return std_logic_vector is
        variable result: std_logic_vector (127 downto 0);
        variable counter_block: std_logic_vector (191 downto 0) := (others => '0');
        variable encrypted_counter:  std_logic_vector (127 downto 0);
        variable trans_plaintext, trans_key, trans_nonce:  std_logic_vector (127 downto 0);
    begin
       trans_plaintext := shift_encript(plaintext);
       trans_key := shift_encript(key);
       trans_nonce := shift_encript(nonce);
       
       counter_block(127 downto 0) := trans_nonce;
       encrypted_counter := encrypt_block(counter_block, trans_key);
       result := trans_plaintext xor encrypted_counter;
       
       result := shift_encript(result);
       return result;
    end function encrypt_ctr;
    
    function decrypt_ctr(ciphertext, key, nonce: std_logic_vector (127 downto 0)) return std_logic_vector is
        variable result: std_logic_vector (127 downto 0);
        variable counter_block: std_logic_vector (191 downto 0) := (others => '0');
        variable encrypted_counter:  std_logic_vector (127 downto 0);
        variable trans_key, trans_nonce:  std_logic_vector (127 downto 0);
    begin
       trans_key := shift_encript(key);
       trans_nonce := shift_encript(nonce); 
              
       counter_block(127 downto 0) := trans_nonce;
       encrypted_counter := encrypt_block(counter_block, trans_key);
       encrypted_counter := shift_encript(encrypted_counter);
       result := ciphertext xor encrypted_counter;
       
       return result;
    end function decrypt_ctr;
begin

    process (clk)
    begin
        if rising_edge (clk) then
            if has_encrypted = '1' then
                sended_encrypted <= testing_encrypted;
            end if;
        end if;
    end process;
    
    process (clk)
    begin
        if rising_edge (clk) then
            if is_recived = '1' then
               -- Testing the operaction through the uart comunication 
               -- for real case change the 'testing_key' for the parameter key 
               to_decrypt <= decrypt_ctr(recived_encrypted, testing_key, testing_nonce);
            end if;
        end if;
    end process;
    
    -- Testing case
    testing_encrypted <= encrypt_ctr(testing_plaintext, testing_key, testing_nonce);
    has_encrypted <= '1';
    testing_decrypted <= decrypt_ctr(testing_encrypted, testing_key, testing_nonce);
    
end Behavioral;
