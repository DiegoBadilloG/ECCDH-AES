library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;
use ieee.math_real.all;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
--use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx leaf cells in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

entity algorithm_25519 is
 generic(
        d_width: integer := 64
    );
    port(
        clk      :  IN   STD_LOGIC;                               --system clock
        reset_n  :  IN   STD_LOGIC;                               --ascynchronous reset
        tx_ena   :  out   STD_LOGIC;                              --initiate transmission
        tx_data  :  OUT  STD_LOGIC_VECTOR(d_width-1 DOWNTO 0);    --data to transmit
        
        rx_busy  :  in  STD_LOGIC;                                --data reception in progress
        rx_error :  in  STD_LOGIC;                                --start, parity, or stop bit error detected
        rx_data  :  IN   STD_LOGIC_VECTOR(d_width-1 DOWNTO 0);    --data received
        tx_busy  :  in  STD_LOGIC ;                               --transmission in progress
        
        received_encrypted: out std_logic_vector(127 downto 0);    --text from external device
        sended_encrypted: in std_logic_vector(127 downto 0);      --fpga to outside
        ready_for_decrypt: out std_logic;
        secret_key: out std_logic_vector(127 downto 0)            --key para AES 128 CTR
    );
end algorithm_25519;

architecture Behavioral of algorithm_25519 is

    constant p : unsigned (255 downto 0) :=    x"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
    constant A_24 : unsigned(255 downto 0) :=  x"000000000000000000000000000000000000000000000000000000000001db41";
    constant Gx : unsigned(255 downto 0) :=    x"0000000000000000000000000000000000000000000000000000000000000009";
    constant n : unsigned(255 downto 0) :=     x"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
    
    signal public_key_Bx: unsigned(255 downto 0);
    signal private_key_A: unsigned(255 downto 0);
    signal public_key_Ax: unsigned(255 downto 0);
    signal num_data_tx: integer  := 0;
    signal aux_secret: unsigned (255 downto 0);
    signal key_generated: std_logic := '0';
    signal public_key_sended: std_logic := '0';
    signal bx_received: std_logic := '0';
    signal has_secret: std_logic := '0';
    
    type state_type_recive is (IDLE, RECEIVE_BX_PART1, RECEIVE_BX_PART2, RECEIVE_BX_PART3, RECEIVE_BX_PART4, WAIT_RX_BUSY, WAIT_RX_FREE);
    signal state_received : state_type_recive := RECEIVE_BX_PART1;
    type state_type_send is (IDLE, SEND_AX_PART1, SEND_AX_PART2, SEND_AX_PART3, SEND_AX_PART4, WAIT_TX_BUSY, WAIT_TX_FREE);
    signal state_sended : state_type_send := IDLE;
    type state_type is (IDLE, WAIT_BY_RECEIVED, CALC_SECRET, ASSIGN_SECRET);
    signal state : state_type := IDLE;
    signal scalar_multiply_done : std_logic := '0';
    
    signal aes_sended: std_logic := '0';
    signal aes_received: std_logic := '0'; 
    type aes_state_type is (IDLE, PART1, PART2,WAIT_TX_BUSY, WAIT_TX_FREE);
    signal aes_state: aes_state_type := IDLE;
    signal aes_state_received: aes_state_type := PART1;
    signal aes_counter: integer := 0;
    signal aux_aes_received: std_logic_vector (127 downto 0);
    
    -- Testing varialbe --
    signal testing_private_key : unsigned(255 downto 0) := x"20a998009346da4d59b2d8ef0f8ea2ca8f9f4a718d926258e8a2d2fc1ec57431";
    signal testing_public_key : unsigned(255 downto 0);
-------------------------
--       ECCDH Methods
-------------------------    

    function generate_random return unsigned  is
            variable seed1, seed2: positive := 1;
            variable x_real: real := 0.0;
            variable x_unsigned: unsigned(255 downto 0) := (others => '0');
            variable segment: unsigned(31 downto 0);
        begin 
            for i in 0 to 7 loop
                uniform(seed1, seed2, x_real);
                segment := to_unsigned(integer(x_real * 4294967295.0), 32);
                x_unsigned(i*32+31 downto i*32) := segment;
            end loop;
            return x_unsigned;
    end function generate_random;
    
    function revert(k: unsigned (255 downto 0)) return unsigned is
        variable result: unsigned (255 downto 0);
        variable j:integer := 255;
    begin
        for i in k'range loop
            result(j) := k(i);
        end loop;
        
        return result;
    end function revert;
    
    function to_little(encrypt: unsigned  (255 downto 0)) return unsigned  is 
        variable result: unsigned  (255 downto 0);
        variable j: integer := 255;
    begin
        for i in 0 to 31 loop
            result(i*8+7 downto i*8) := encrypt(j downto j-7);
            j := j - 8;
        end loop;
        
        return result;
    end function to_little;
    
   function clamp(n : unsigned (255 downto 0)) return unsigned is
        variable result : unsigned(255 downto 0);
    begin
        -- Clear the 3 least significant bits
        result := n;
        result(2 downto 0) := (others => '0');

        -- Set bit 254
        result(254) := '1';

        -- Clear bit 255
        result(255) := '0';

        return result;
    end function clamp;
    
    function mod_exp(base, exp, module : unsigned(255 downto 0)) return unsigned is
        variable result : unsigned(255 downto 0) := x"0000000000000000000000000000000000000000000000000000000000000001";
        variable b : unsigned(255 downto 0) := base;
        variable e : unsigned(255 downto 0) := exp;
    begin
        for i in 0 to 255 loop
            exit when e <= 0;
            if e(i) = '1' then
                result := (result * b) mod module;
            end if;
            e := e(255 downto 1) & '0';
            b := (b * b) mod module;
        end loop;
        return result;
    end function mod_exp;
    
    
    function mod_exp_v2(base, exp, module : signed(259 downto 0)) return signed is
        variable result : signed(259 downto 0) := (others => '0');
        variable b : signed(259 downto 0) := base;
        variable e : signed(259 downto 0) := exp;
    begin
        result(0) := '1';
        for i in 0 to 258 loop
            exit when e <= 0;
            if e(i) = '1' then
                result := (result * b) mod module;
            end if;
            e := e(258 downto 1) & '0';
            b := (b * b) mod module;
        end loop;
        return result;
    end function mod_exp_v2;
    
    function cswap(swap : std_logic; x2, x3 : signed(256 downto 0)) return signed  is
    begin
        if swap = '1' then
            return x3 & x2;
        end if;
        
        return x2 & x3;
    end function cswap;
    
    function montgomery_ladder(k, u : unsigned(255 downto 0)) return unsigned is
        variable x1, x3, temp, temp2, temp3: signed(256 downto 0);
        variable x2, z2, z3: signed(256 downto 0) := (others => '0');
        variable A, AA, B, BB, E, C, D, DA, CB : signed(256 downto 0);
        variable kt : std_logic;
        variable swapped : signed (513 downto 0);
        variable module: signed (256 downto 0) := signed(resize(p, 257));
        variable temp4, temp5, temp6: signed (259 downto 0):= (others => '0');
        variable tempResult: signed(259 downto 0);
        variable op: unsigned (255 downto 0);
    begin
        x1 := signed(resize(u, 257));
        x2(0) := '1';
        x3 := signed(resize(u, 257));
        z3(0) := '1';
        for t in k'range loop
            kt := k(t);
            swapped := cswap(kt, x2, x3);
            x2 := swapped (513 downto 257);
            x3 := swapped(256 downto 0);
            swapped := cswap(kt, z2, z3);
            z2 := swapped (513 downto 257);
            z3 := swapped(256 downto 0);
            
            A := (x2 + z2) mod module;
            AA := (A * A) mod module;
            B := (x2 - z2) mod module;
            BB := (B * B) mod module;
            E := (AA - BB) mod module;
            C := (x3 + z3) mod module;
            D := (x3 - z3) mod module;
            DA := (D * A) mod module;
            CB := (C * B) mod module;
            x3 := (DA + CB) mod module;
            x3 := (x3 * x3) mod module;
            z3 := (DA - CB) mod module;
            z3 := (z3 * z3) mod module;
            z3 := (z3 * x1) mod module;
            x2 := (AA * BB) mod module;
            temp := (signed(resize(A_24, 257)) * E) mod module;
            z2 := (E * (AA + temp)) mod module;
            
            swapped := cswap(kt, x2, x3);
            x2 := swapped (513 downto 257);
            x3 := swapped(256 downto 0);
            swapped := cswap(kt, z2, z3);
            z2 := swapped (513 downto 257);
            z3 := swapped(256 downto 0);
        end loop;
           
        temp := signed(resize(mod_exp(unsigned(resize(z2,256)), p-2, p), 257));
        temp2 := (x2 * temp) mod module;
        
        return unsigned(resize(temp2,256));
    end function montgomery_ladder;
    
    function x25519(k , u : unsigned(255 downto 0)) return unsigned is
        variable k_int : unsigned(255 downto 0);
         variable u_int : unsigned(255 downto 0);
        variable r_int : unsigned(255 downto 0);
    begin
        k_int := to_little(k);
        k_int := clamp(k_int);
        u_int := to_little(u);
        r_int := montgomery_ladder(k_int, u);
        
        r_int := to_little(r_int);
        return r_int;
    end function x25519;
    
begin
------------------------------
--      Main execution
------------------------------
    process(rx_busy)
        variable zero: std_logic_vector (63 downto 0) := (others => '0');
    begin
        if falling_edge (rx_busy) then
            --
            --  REceiving B public key for ECCDH
            --
            if bx_received  = '0' then
                case state_received is
                     when RECEIVE_BX_PART1 => 
                        public_key_Bx(255 downto 192) <= unsigned(rx_data);
                        state_received <= RECEIVE_BX_PART2;
                     when RECEIVE_BX_PART2 => 
                        public_key_Bx(191 downto 128) <= unsigned(rx_data);
                        state_received <= RECEIVE_BX_PART3;
                    when RECEIVE_BX_PART3 => 
                        public_key_Bx(127 downto 64) <= unsigned(rx_data);
                        state_received <= RECEIVE_BX_PART4;
                    when RECEIVE_BX_PART4 => 
                        public_key_Bx(63 downto 0) <= unsigned(rx_data);
                        state_received <= IDLE;
                        bx_received <= '1';
                    when others => 
                        null;
                end case;
            end if;
            --
            -- Receiving AES cipher text. After it is recived the data is sended to AES module
            --
            if has_secret = '1' and aes_received = '0' then
                case aes_state_received is
                    when PART1 => 
                        aux_aes_received(127 downto 64) <= rx_data;
                        aes_state_received <= PART2;
                    when PART2 => 
                        aux_aes_received(63 downto 0) <= rx_data;
                        aes_state_received <= IDLE;
                        ready_for_decrypt <= '1';
                        aes_received <= '1';
                    when others => 
                        null;
                end case;
            end if;
        end if;
    end process;
    
    process (clk)
    begin
        if rising_edge (clk) and aes_received = '1' then
            received_encrypted <= aux_aes_received;
        end if;
    end process;
    
    process(clk)
    begin
        if rising_edge (clk) then
            -- Sending A public key through the aurt to B
             if public_key_sended = '0' and key_generated = '1' then 
                 case state_sended is 
                    when IDLE => 
                        state_sended <= WAIT_TX_BUSY;
                    when WAIT_TX_BUSY =>
                        tx_ena <= '1';
                        case num_data_tx is
                            when 0 =>
                                state_sended <= SEND_AX_PART1;
                            when 1 => 
                                 state_sended <= SEND_AX_PART2;
                            when 2 => 
                                 state_sended <= SEND_AX_PART3;
                            when 3 =>
                                 state_sended <= SEND_AX_PART4;
                            when others => 
                                state_sended <= WAIT_TX_FREE;
                                end case;
                    when WAIT_TX_FREE => 
                        tx_ena <= '0';
                        if tx_busy = '0' then 
                            state_sended <= WAIT_TX_BUSY;
                        end if;
                    when SEND_AX_PART1 =>
                        tx_data <= std_logic_vector(public_key_Ax(255 downto 192));
                        num_data_tx <= 1;
                        state_sended <= WAIT_TX_FREE;
                    when SEND_AX_PART2 =>
                        tx_data <= std_logic_vector(public_key_Ax(191 downto 128));
                        num_data_tx <= 2;
                        state_sended <= WAIT_TX_FREE;
                    when SEND_AX_PART3 => 
                        tx_data <= std_logic_vector(public_key_Ax(127 downto 64));
                        num_data_tx <= 3;
                        state_sended <= WAIT_TX_FREE;
                    when SEND_AX_PART4 => 
                        tx_data <= std_logic_vector(public_key_Ax(63 downto 0));
                        num_data_tx <= 4;
                        state_sended <= WAIT_TX_FREE;
                    when others => 
                        null;
                 end case;
             end if;
             
            --
            -- Sending AES encrypted texto to B. The text has been 
            -- received  through the inputs once the AES module encrypted the plaint text.
            ---
            if aes_sended = '0' and has_secret = '1' then
                case aes_state is
                    when IDLE => 
                        aes_state <= WAIT_TX_BUSY;
                    when WAIT_TX_BUSY => 
                        tx_ena <= '1';
                        case aes_counter is
                            when 0 => 
                                aes_state <= PART1;
                            when 1 => 
                                aes_state <= PART2;
                            when others => 
                                 aes_state <= WAIT_TX_FREE;
                        end case;
                    when WAIT_TX_FREE => 
                        tx_ena <= '0';
                        if tx_busy = '0' then 
                            aes_state <= WAIT_TX_BUSY;
                        end if;
                    when PART1 => 
                        tx_data <= sended_encrypted(127 downto 64);
                        aes_counter <= 1;
                        aes_state <= WAIT_TX_FREE;
                    when PART2 => 
                        tx_data <= sended_encrypted(63 downto 0);
                        aes_counter <= 2;
                        aes_sended <= '1';
                        aes_state <= WAIT_TX_FREE;
                    when others => 
                        null;
                end case;
            end if;
        end if;
    end process;   
    
    process (clk)
    --
    -- When the public key of B is received  the shared secret is been calculated
    --
    begin
        if rising_edge (clk) then
            case state is
                when IDLE =>
                    if has_secret = '0' and bx_received = '1' then
                        state <= CALC_SECRET;
                    end if;
                when CALC_SECRET => 
                    aux_secret <= x25519(private_key_A, public_key_BX);
                    scalar_multiply_done <= '1';
                    state <= ASSIGN_SECRET;
                when ASSIGN_SECRET => 
                    if scalar_multiply_done = '1' then
                        has_secret <= '1';
                        secret_key <= std_logic_vector(aux_secret(255 downto 128));
                        state <= IDLE;
                    end if;
                when others => 
                    state <= IDLE;
            end case;
        end if;
    end process;
    
    
    -- Testting case
     private_key_A <= generate_random;
     public_key_Ax <= x25519(testing_private_key,Gx);
     key_generated <= '1';
end Behavioral;
