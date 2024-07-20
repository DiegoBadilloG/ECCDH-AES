library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;
use ieee.math_real.all;

entity algorithm_256r1 is
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
        
        recived_encrypted: out std_logic_vector(127 downto 0);    --text from external device
        sended_encrypted: in std_logic_vector(127 downto 0);      --fpga to outside
        ready_for_decrypt: out std_logic;
        secret_key: out std_logic_vector(127 downto 0)            --key para AES 128 CTR
    );
end algorithm_256r1;

architecture Behavioral of algorithm_256r1 is
    constant p : unsigned (255 downto 0) := x"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
    constant a : unsigned(255 downto 0) := x"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
    constant b : unsigned(255 downto 0) := x"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
    constant Gx : unsigned(255 downto 0) := x"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    constant Gy : unsigned(255 downto 0) := x"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    constant n : unsigned(255 downto 0) := x"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
    constant MAX_INT : real := 2147483647.0;
    
    signal public_key_Bx: unsigned(255 downto 0);
    signal public_key_By: unsigned(255 downto 0);
    signal private_key_A: unsigned(255 downto 0);
    signal public_key_Ax: unsigned(255 downto 0);
    signal public_key_Ay: unsigned(255 downto 0);
    signal num_data_tx: integer  := 0;
    signal num_data_tx_y: integer := 0;
    signal aux_key: unsigned (511 downto 0);
    signal aux_secret: unsigned (511 downto 0);
    signal key_generated: std_logic := '0';
    signal public_key_sended_y: std_logic := '0';
    signal by_recived: std_logic := '0';
    signal has_secret: std_logic := '0';
    
    type state_type is (IDLE, WAIT_BY_RECEIVED, CALC_SECRET, ASSIGN_SECRET);
    signal state : state_type := IDLE;
    signal scalar_multiply_done : std_logic := '0';
    type state_type_send is (IDLE, SEND_AX_PART1, SEND_AX_PART2, SEND_AX_PART3, SEND_AX_PART4, WAIT_TX_BUSY, WAIT_TX_FREE, SEND_AY_PART1, SEND_AY_PART2, SEND_AY_PART3, SEND_AY_PART4);
    signal state_sended : state_type_send := IDLE;
    type state_type_recive is (IDLE, RECEIVE_BX_PART1, RECEIVE_BX_PART2, RECEIVE_BX_PART3, RECEIVE_BX_PART4, WAIT_RX_BUSY, WAIT_RX_FREE, RECEIVE_BY_PART1, RECEIVE_BY_PART1_WAIT, RECEIVE_BY_PART2, RECEIVE_BY_PART3, RECEIVE_BY_PART4);
    signal state_recived : state_type_recive := RECEIVE_BX_PART1;
    
    signal aes_sended: std_logic := '0';
    signal aes_recived: std_logic := '0'; 
    type aes_state_type is (IDLE, PART1, PART2,WAIT_TX_BUSY, WAIT_TX_FREE);
    signal aes_state: aes_state_type := IDLE;
    signal aes_state_recived: aes_state_type := PART1;
    signal aes_counter: integer := 0;
    signal aux_aes_recived: std_logic_vector (127 downto 0);
    
    
    -- Testing varialbes
    signal testing_on_curve: std_logic;
    signal testing_a: unsigned (255 downto 0) := x"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d8aa7972";
    signal testing_b: unsigned (255 downto 0) := x"8b5d90bf0c91e1fab33a0ae814aeffb946e76f97d8faec8b7a4cf33ac892c01d";

-------------------------
--       ECCDH Methods
-------------------------    
    function xgcd_v2 (value: unsigned(259 downto 0); modular: unsigned(255 downto 0)) return unsigned is
        -- Extended euclidean algorithm implemenatation for 260 bits a value.
        variable u1, u2, u3, v1, v2, v3,r: signed (260 downto 0);
        variable g0 : signed(260 downto 0);
        variable  g1 : signed(260 downto 0);
        variable y : signed(260 downto 0);
        variable result : unsigned (255 downto 0);
        constant MAX_ITERATIONS: integer := 400; 
        begin
            g0 := signed(resize(modular, 261));
            g1 := signed(resize(value, 261)); 
            
            u1 := (others => '0');
            u1(0) := '1';
            v2 := (others => '0');
            v2(0) := '1';
            r := (others => '0');
            r(0) :=  '1';
            
            u2 := (others => '0');
            v1 := (others => '0');
            
            for i in 0 to MAX_ITERATIONS loop
                exit when r <= 0;
                y := g0 / g1;
                r := resize(g0 - y * g1, 261);
                u3 := resize(u1 - y * u2, 261);
                v3 := resize(v1 - y * v2, 261);
        
                if r > 0 then
                    g0 := g1;
                    g1 := resize(r, 261);
                    u1 := u2;
                    u2 := u3;
                    v1 := v2;
                    v2 := v3;
                end if;
            end loop;
            
            if v2 < 0 then 
                v2 := v2 + signed(resize(modular, 261));
            end if; 
        
            result := unsigned(v2(255 downto 0));
            return result;
    end function xgcd_v2;

    function new_add_points_v3 (x1, y1, x2, y2 : unsigned(255 downto 0)) return unsigned is 
        variable zero: unsigned (255 downto 0) := (others => '0');
        variable x1_sg, y1_sg, x2_sg, y2_sg: signed (256 downto 0);
        variable temp1: unsigned (515 downto 0);
        variable temp2: unsigned (259 downto 0);
        variable temp3: unsigned (255 downto 0);
        variable temp4: unsigned (771 downto 0);
        variable s: unsigned(255 downto 0);
        variable pomp1: signed (256 downto 0);
        variable pomp2: signed (256 downto 0);
        variable pomp2_usg: unsigned (259 downto 0);
        variable pomp3: unsigned (255 downto 0);
        variable pomp4: signed (513 downto 0);
        
        variable aux: unsigned (511 downto 0);
        variable aux_sg: signed (513 downto 0);
        variable x3, y3: unsigned (255 downto 0);
    begin
        x1_sg := signed(resize(x1, 257));
        x2_sg := signed(resize(x2, 257));
        y1_sg := signed(resize(y1, 257));
        y2_sg := signed(resize(y2, 257));
    
        if x1 = zero and y1 =  zero then 
            return x2 & y2;
        elsif x2 = zero and y2 =  zero then
            return x1 & y1;
        elsif x1 = x2 and y1 = y2 then
            temp1 := resize(3 * x1 * x1 + a, 516);
            temp2 := resize(2 * y1, 260);
            temp3 := xgcd_v2(temp2, p);
            temp4 := temp1 * temp3;
            s := temp4 mod p;
        else
            pomp1 := y2_sg - y1_sg;
            if pomp1(pomp1'high) = '1' then
                pomp1 := pomp1 mod signed(resize(p, 257));
            end if;
            pomp2 := x2_sg - x1_sg;
            if pomp2(pomp2'high) = '1' then
                pomp2 := pomp2 mod signed(resize(p, 257));
            end if;
            pomp2_usg := unsigned(resize(pomp2, 260));
            pomp3 := xgcd_v2(pomp2_usg, p);
            pomp4 := pomp1 * signed(resize(pomp3, 257));
            s := unsigned(pomp4) mod p;
        end if;
        
        aux := s * s - x1 - x2;
        x3 := aux mod p;
        aux_sg := signed(resize(s, 257)) * (x1_sg - signed(resize(x3, 257))) - y1_sg;
        if aux_sg(aux_sg'high) = '1' then
            aux_sg := aux_sg mod signed(resize(p, 514));
        end if;
        y3 := unsigned(aux_sg) mod p;
        
        return x3 & y3;
    end function new_add_points_v3;

    function scalar_multiply_v2 (x1, y1, scalar: unsigned  (255 downto 0)) return unsigned is 
        variable result: unsigned (511 downto 0) := (others => '0');
        variable result_x, result_y: unsigned (255 downto 0);
    begin
        result_x := (others => '0');
        result_y := (others => '0');
        
        for i in scalar'range loop
            result := new_add_points_v3(result_x, result_y, result_x, result_y);
            result_x := result (511 downto 256);
            result_y := result (255 downto 0);           
            if scalar(i) = '1' then
                result := new_add_points_v3(result_x, result_y, x1, y1);
                result_x := result (511 downto 256);
                result_y := result (255 downto 0);
            end if;
        end loop;
    
        return result;
    end function scalar_multiply_v2;

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
       
        
     function is_on_point(x,y: unsigned(255 DOWNTO 0)) return std_logic is 
        variable left, right: unsigned  (255 downto 0);
        variable result: std_logic := '0';
     begin 
        left := (y * y) mod p;
        right := ((x*x*x) + a * x + b) mod p;
        if left = right then
            result := '1';
        end if;
        return result;
     end function  is_on_point;
    
begin
------------------------------
--      Main execution
------------------------------
    process (rx_busy)
        variable zero: std_logic_vector (63 downto 0) := (others => '0');
    begin
        if falling_edge (rx_busy) then
            --
            --  REceiving B public key for ECCDH
            --
            if by_recived = '0'  then
                case state_recived is
                    when RECEIVE_BX_PART1 => 
                        public_key_Bx(255 downto 192) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BX_PART2;
                    when RECEIVE_BX_PART2 => 
                        public_key_Bx(191 downto 128) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BX_PART3;
                    when RECEIVE_BX_PART3 => 
                        public_key_Bx(127 downto 64) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BX_PART4;
                    when RECEIVE_BX_PART4 => 
                        public_key_Bx(63 downto 0) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BY_PART1;
                    when RECEIVE_BY_PART1 => 
                        public_key_By(255 downto 192) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BY_PART2;
                    when RECEIVE_BY_PART2 => 
                        public_key_By(191 downto 128) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BY_PART3;
                    when RECEIVE_BY_PART3 => 
                        public_key_By(127 downto 64) <= unsigned(rx_data);
                        state_recived <= RECEIVE_BY_PART4;
                    when RECEIVE_BY_PART4 => 
                        public_key_By(63 downto 0) <= unsigned(rx_data);
                        by_recived <= '1';
                        state_recived <= IDLE;
                    when others => 
                        null;
                end case;
           end if;
            
            --
            -- Receiving AES cipher text. After it is recived the data is sended to AES module
            --
            if has_secret = '1' and aes_recived = '0' then
                case aes_state_recived is
                    when PART1 => 
                        aux_aes_recived(127 downto 64) <= rx_data;
                        aes_state_recived <= PART2;
                    when PART2 => 
                        aux_aes_recived(63 downto 0) <= rx_data;
                        aes_state_recived <= IDLE;
                        ready_for_decrypt <= '1';
                        aes_recived <= '1';
                    when others => 
                        null;
                end case;
            end if;
        end if;
    end process;
    
    process (clk)
    begin
        if rising_edge (clk) and aes_recived = '1' then
            recived_encrypted <= aux_aes_recived;
        end if;
    end process;


    process (clk)
    begin
        if  rising_edge(clk) then
            -- Sending A public key through the aurt to B
            if public_key_sended_y = '0' and key_generated = '1' then
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
                                case num_data_tx_y is 
                                    when 0 =>
                                        state_sended <= SEND_AY_PART1;
                                    when 1 => 
                                         state_sended <= SEND_AY_PART2;
                                    when 2 => 
                                         state_sended <= SEND_AY_PART3;
                                    when 3 =>
                                         state_sended <= SEND_AY_PART4;
                                    when others => 
                                        state_sended <= WAIT_TX_FREE;
                                    end case;
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
                    when SEND_AY_PART1 => 
                        tx_data <= std_logic_vector(public_key_Ay(255 downto 192));
                        num_data_tx_y <= 1;
                        state_sended <= WAIT_TX_FREE;
                    when SEND_AY_PART2 => 
                        tx_data <= std_logic_vector(public_key_Ay(191 downto 128));
                        num_data_tx_y <= 2;
                        state_sended <= WAIT_TX_FREE;
                    when SEND_AY_PART3 => 
                        tx_data <= std_logic_vector(public_key_Ay(127 downto 64));
                        num_data_tx_y <= 3;
                        state_sended <= WAIT_TX_FREE;
                    when SEND_AY_PART4 => 
                        tx_data <= std_logic_vector(public_key_Ay(63 downto 0));
                        num_data_tx_y <= 4;
                        public_key_sended_y <= '1';
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
        if rising_edge(clk) then
            case state is
                when IDLE =>
                    if has_secret = '0' then
                        if by_recived = '1' then
                            state <= CALC_SECRET;
                        end if;
                    end if;
                when CALC_SECRET =>
                    aux_secret <= scalar_multiply_v2(public_key_Bx, public_key_By, private_key_A);
                    scalar_multiply_done <= '1';
                    state <= ASSIGN_SECRET;
                when ASSIGN_SECRET =>
                    if scalar_multiply_done = '1' then
                        has_secret <= '1';
                        secret_key <= std_logic_vector(aux_secret(511 downto 384));
                        state <= IDLE;
                    end if;
                when others =>
                    state <= IDLE;
            end case;
        end if;
    end process;
    
    -- Testting case
    private_key_A <= generate_random; 
    aux_key <= scalar_multiply_v2(Gx, Gy, private_key_A);
    public_key_Ax <= aux_key(511 downto 256);
    public_key_Ay <= aux_key(255 downto 0);
    key_generated <= '1';
    testing_on_curve <= is_on_point(testing_a, testing_b);
    
    
end Behavioral;
