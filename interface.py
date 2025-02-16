# ...existing code...

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import socket
import threading

def string_to_binary(s):
    # Usa 'latin-1' para suportar caracteres ASCII estendidos (T5)
    encoded = s.encode('latin-1', errors='replace')
    return ''.join(format(byte, '08b') for byte in encoded)

def manchester_encode(binary_str):
    # Algoritmo Manchester simples (T6)
    encoding = []
    for bit in binary_str:
        if bit == '0':
            encoding.extend(['0', '1'])
        else:
            encoding.extend(['1', '0'])
    return ''.join(encoding)

def manchester_decode(encoded_str):
    # Decodifica sequência Manchester (T8)
    bits = []
    for i in range(0, len(encoded_str), 2):
        pair = encoded_str[i:i+2]
        # Par '01' => bit '0'; Par '10' => bit '1'
        if pair == '01':
            bits.append('0')
        elif pair == '10':
            bits.append('1')
    return ''.join(bits)

class App(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master.title("Interface de Codificação")
        self.pack(fill=tk.BOTH, expand=True)

        self.input_var = tk.StringVar()
        self.input_var.trace("w", self.update_output)

        self.binary_label = None
        self.manchester_label = None
        self.fig = None
        self.ax_bin = None
        self.ax_manch = None
        self.canvas = None

        self.create_widgets()
        self.create_plot()

        # Inicia thread de servidor para receber dados (T3, T7)
        threading.Thread(target=self.start_server, daemon=True).start()

    def create_widgets(self):
        frame_inputs = ttk.Frame(self)
        frame_inputs.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(frame_inputs, text="Entrada:").grid(row=0, column=0, sticky=tk.W)
        entry_input = ttk.Entry(frame_inputs, textvariable=self.input_var)
        entry_input.grid(row=0, column=1, sticky=tk.EW, padx=5)

        ttk.Label(frame_inputs, text="Binário:").grid(row=1, column=0, sticky=tk.W)
        self.binary_label = ttk.Label(frame_inputs, text="", anchor="w")
        self.binary_label.grid(row=1, column=1, sticky=tk.EW, padx=5)

        ttk.Label(frame_inputs, text="Manchester:").grid(row=2, column=0, sticky=tk.W)
        self.manchester_label = ttk.Label(frame_inputs, text="", anchor="w")
        self.manchester_label.grid(row=2, column=1, sticky=tk.EW, padx=5)

        # Botão para enviar a mensagem para o outro lado (T7)
        send_button = ttk.Button(frame_inputs, text="Enviar", command=self.send_message)
        send_button.grid(row=3, column=0, columnspan=2, pady=5)

        for i in range(2):
            frame_inputs.columnconfigure(i, weight=1)

    def create_plot(self):
        self.fig, (self.ax_bin, self.ax_manch) = plt.subplots(2, 1, figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True)

    def update_output(self, *args):
        text_input = self.input_var.get()
        binary_str = string_to_binary(text_input)
        manchester_str = manchester_encode(binary_str)

        # Mostra binário e Manchester (T1, T2)
        self.binary_label.configure(text=binary_str)
        self.manchester_label.configure(text=manchester_str)

        # Atualiza gráfico binário
        self.ax_bin.clear()
        bin_values = [int(bit) for bit in binary_str] if binary_str else []
        self.ax_bin.step(range(len(bin_values)), bin_values, where='post')
        self.ax_bin.set_ylim(-0.5, 1.5)
        self.ax_bin.set_title("Binário")

        # Atualiza gráfico Manchester
        self.ax_manch.clear()
        manch_values = [int(bit) for bit in manchester_str] if manchester_str else []
        self.ax_manch.step(range(len(manch_values)), manch_values, where='post')
        self.ax_manch.set_ylim(-0.5, 1.5)
        self.ax_manch.set_title("Manchester")

        self.fig.tight_layout()
        self.canvas.draw()

    def send_message(self):
        # Simples envio por socket TCP localhost (T3, T7)
        text_input = self.input_var.get()
        bin_data = string_to_binary(text_input)
        manch_data = manchester_encode(bin_data)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("127.0.0.1", 9999))
                s.sendall(manch_data.encode('utf-8'))
            except:
                pass

    def start_server(self):
        # Servidor que recebe dados e faz o processo inverso (T8)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 9999))
            server.listen(1)
            while True:
                conn, _ = server.accept()
                data = conn.recv(4096)
                if data:
                    received_manch = data.decode('utf-8')
                    print("Recebido (Manchester):", received_manch)
                    # Decodifica Manchester para binário e vice-versa
                    bits = manchester_decode(received_manch)
                    print("Recebido (Binário):", bits)
                    # Aqui poderíamos reverter para texto, se quisermos
                    # Exemplo: (T4, se houvesse criptografia adicional)
                    try:
                        # Tenta converte bits em bytes e depois em texto
                        msg_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
                        msg_text = msg_bytes.decode('latin-1', errors='replace')
                        print("Recebido:", msg_text)
                    except:
                        pass

if __name__ == "__main__":
    root = tk.Tk()
    app = App(master=root)
    app.mainloop()