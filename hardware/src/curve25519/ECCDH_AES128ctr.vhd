library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

entity ECCDH_AES128ctr is
--  Port (
--  clk_sistema: in std_logic
--   );
end ECCDH_AES128ctr;

architecture Behavioral of ECCDH_AES128ctr is
    constant CLOCK_PERIOD : time := 10 ns;  --CLOCK PERIOD (100 MHz)
    signal clk : std_logic := '0';  -- CLOCK SIGNAL
    signal reset  : STD_LOGIC := '1';  -- RESET TEST BENCH
    
    component algorithm_25519 is 
        generic(
            d_width: integer := 64
        );
        port(
            clk      :  IN   STD_LOGIC;                             --system clock
            reset_n  :  IN   STD_LOGIC;                             --ascynchronous reset
            tx_ena   :  out   STD_LOGIC;                            --initiate transmission
            tx_data  :  OUT  STD_LOGIC_VECTOR(d_width-1 DOWNTO 0);  --data to transmit
            
            rx_busy  :  in  STD_LOGIC;                              --data reception in progress
            rx_error :  in  STD_LOGIC;                              --start, parity, or stop bit error detected
            rx_data  :  IN   STD_LOGIC_VECTOR(d_width-1 DOWNTO 0);  --data received
            tx_busy  :  in  STD_LOGIC;                              --transmission in progress
            
            received_encrypted: out std_logic_vector(127 downto 0);  --fpga to outside
            sended_encrypted: in std_logic_vector(127 downto 0);    --text from external device
            ready_for_decrypt: out std_logic;
            secret_key: out std_logic_vector(127 downto 0)
        );
    end component algorithm_25519;
    
    
    component uart is 
        GENERIC(
            clk_freq  :  INTEGER    := 50_000_000;                   --frequency of system clock in Hertz
            baud_rate :  INTEGER    := 19_200;                       --data link baud rate in bits/second
            os_rate   :  INTEGER    := 16;                           --oversampling rate to find center of receive bits (in samples per baud period)
            d_width   :  INTEGER    := 64;                           --data bus width
            parity    :  INTEGER    := 1;                            --0 for no parity, 1 for parity
            parity_eo :  STD_LOGIC  := '0'                           --'0' for even, '1' for odd parity
        );        
        port(
            clk      :  IN   STD_LOGIC;                              --system clock
            reset_n  :  IN   STD_LOGIC;                              --ascynchronous reset
            tx_ena   :  IN   STD_LOGIC;                              --initiate transmission
            tx_data  :  IN   STD_LOGIC_VECTOR(d_width-1 DOWNTO 0);   --data to transmit
            rx       :  IN   STD_LOGIC;                              --receive pin
            rx_busy  :  OUT  STD_LOGIC;                              --data reception in progress
            rx_error :  OUT  STD_LOGIC;                              --start, parity, or stop bit error detected
            rx_data  :  OUT  STD_LOGIC_VECTOR(d_width-1 DOWNTO 0);   --data received
            tx_busy  :  OUT  STD_LOGIC;                              --transmission in progress
            tx       :  OUT  STD_LOGIC                               --transmit pin
        );
       end component uart;
       
      component AES_128_CTR is
        generic(
            d_width: integer := 64
        );
        port(
            clk: in std_logic;
            
            key: in std_logic_vector (127 downto 0);
            recived_encrypted: in std_logic_vector (127 downto 0); 
            is_recived: in std_logic;
            sended_encrypted: out std_logic_vector (127 downto 0)
        );
      end component AES_128_CTR;
    
    -- UART CONSTANTS
    constant CLK_FREQ:  integer := 50_000_000;
    constant BAUD_RATE: integer := 19_200;
    constant OS_RATE:   integer := 16;
    constant D_WIDTH:   integer := 64;
    constant PARITY:    integer := 1;
    constant PARITY_EO: std_logic := '0';
    
    -- SIGNALS FOR SENDING / RECIVING DATA IN ECCDH ALGORITHM 
    signal tx_data: STD_LOGIC_VECTOR (63 downto 0);
    signal rx_data: STD_LOGIC_VECTOR (63 downto 0);
    signal rx_busy: std_logic;
    signal tx_busy: std_logic; 
    signal tx: std_logic;
    signal rx: std_logic;
    signal tx_ena: std_logic;
    signal rx_error: std_logic;
    
    -- SIGNALS FOR AES ALGORITHM
    signal aes_key: std_logic_vector (127 downto 0);
    signal AES_rx: std_logic_vector (127 downto 0); 
    signal AES_tx: std_logic_vector (127 downto 0);
    signal aes_decrypt_ready: std_logic;
    
begin 
    uart_component: uart
        generic map (
            clk_freq  =>  CLK_FREQ,
            baud_rate =>  BAUD_RATE,
            os_rate   =>  OS_RATE,
            d_width   =>  D_WIDTH,
            parity    =>  PARITY,
            parity_eo => PARITY_EO
         )
         port map(clk => clk, reset_n => reset, tx_ena => tx_ena,
          tx_data => tx_data, rx => rx, rx_busy=> rx_busy, rx_error => rx_error,
          rx_data => rx_data, tx_busy => tx_busy, tx => tx 
         );
         
    curve25519_component: algorithm_25519
        port map(clk => clk, reset_n => reset, rx_busy => rx_busy,
            rx_error => rx_error, rx_data => rx_data, tx_ena => tx_ena, tx_data => tx_data,
            tx_busy => tx_busy, secret_key => aes_key, received_encrypted => AES_rx,
            sended_encrypted => AES_tx, ready_for_decrypt => aes_decrypt_ready
        );
        
    AES_128_CTR_component: AES_128_CTR
        port map(clk => clk, key => aes_key,
            recived_encrypted => AES_rx, sended_encrypted => AES_tx, 
            is_recived => aes_decrypt_ready 
        );
        
        
    -- THE FOLLOWED COMPONENS ARE NEEDED FOR CORRECT SIMULATION 
    -- NOTE THAT THE SENDED DATA FROM THE FPGA THROUGH THE UART ARE THE
    --RECIVED DATA. THE DEVICE IS RECIBING THE SAME DATA IT IS SENDED. 
    -- COMMENT THIS COMPONENTS FOR PROJECT SINTHESIS
    CLOCK:
        process
        begin
            wait for 10 ns;
            clk <= not clk;
            if now > 500 ms then
                wait;
            end if;
        end process;

    RESET_n:
        process
        begin
            wait for 4 ns;
            reset <= '0';
            wait for 80 ns;
            reset <= '1';
            wait;
        end process;
        
    STIMULI_RX:
        process
        begin
            wait until rising_edge (reset);
            wait until rx_busy = '1';
            for i in 0 to 255 loop
                wait until rx_busy = '0';
                wait until rising_edge (clk);
            end loop;
        end process;

    LOOP_BACK:
        rx <= tx;
end Behavioral;