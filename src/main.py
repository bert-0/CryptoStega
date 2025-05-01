import os
import hashlib
import json
import secrets
import base64
import blake3 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from collections import OrderedDict

# Segurança da Interface
class UIStateManager:
    def __init__(self, root):
        self.root = root
        self.disabled_widgets = []
        
    def disable_ui(self):
        # Desabilita todos os widgets sensíveis
        for widget in self.root.winfo_children():
            if isinstance(widget, (ttk.Button, ttk.Entry, tk.Text)):
                if widget['state'] == 'normal':
                    widget.config(state='disabled')
                    self.disabled_widgets.append(widget)
                    
    def enable_ui(self):
        # Reabilita os widgets
        for widget in self.disabled_widgets:
            widget.config(state='normal')
        self.disabled_widgets = []

# Proteção da senha na memória
class SecureString:
    def __init__(self, string):
        self._data = bytearray(string.encode('utf-8'))
        self._cleared = False
        
    def __del__(self):
        if not self._cleared:
            self.clear()
        
    def clear(self):
        if hasattr(self, '_data') and self._data is not None:
            # Sobrescreve os dados na memória
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data = None
        self._cleared = True
        
    def get(self):
        if self._cleared or not hasattr(self, '_data') or self._data is None:
            raise ValueError("Dados sensíveis já foram limpos")
        return bytes(self._data).decode('utf-8')
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()

class CriptografiaHibrida:
    def __init__(self, root, iteracoes_kdf=150_000):
        self.root = root
        self.root.title("CryptoStega - Hybrid Cryptography")
        self.root.resizable(False, False)
        self.root.geometry("900x750")
        self.MAX_TEXT_SIZE = 10 * 1024 * 1024  # 10MB
        self.ui_state = UIStateManager(root)
        
        # Verifica se o arquivo de ícone existe
        icon_path = "iconeCripto.ico"
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        else:
            print("Warning: 'icon.ico' not found. Using default icon.")
        
        # Configurações
        self.iteracoes_kdf = iteracoes_kdf
        self.tamanho_minimo = 1024
        self.tamanho_salt = 32
        self.tamanho_iv = 16
        self.caracteres = self.gerar_alfabeto_completo()
        
        # Interface
        self.criar_interface()
        self.configurar_estilos()

    def gerar_alfabeto_completo(self):
        base = (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "áàâãäåéèêëíìîïóòôõöúùûüçñ"
            "0123456789"
            "!@#$%&*()_-+=[]{}|;:,.<>?/ \n\t"
        )
        return list(OrderedDict.fromkeys(base))

    def configurar_estilos(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', font=('Helvetica', 10))
        style.configure('TFrame', background='#f5f5f5')
        style.configure('TLabel', background='#f5f5f5')
        style.configure('TButton', padding=5)
        style.configure('Accent.TButton', foreground='white', background='#2c7be5')
        style.configure('SecButton.TButton', foreground='white', background='#6c757d')
        style.map('Accent.TButton', background=[('active', '#1a68d1')])
        style.map('SecButton.TButton', background=[('active', '#5a6268')])
   
    def criar_interface(self):
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        self.abas = ttk.Notebook(main_frame)
        self.aba_cripto = ttk.Frame(self.abas)
        self.aba_descripto = ttk.Frame(self.abas)
        self.abas.add(self.aba_cripto, text="🔒 Criptografar")
        self.abas.add(self.aba_descripto, text="🔓 Descriptografar")
        self.abas.pack(expand=True, fill=tk.BOTH)
        
        self.criar_aba_criptografia()
        self.criar_aba_descriptografia()
        
        self.status_var = tk.StringVar(value="Pronto para operações de criptografia")
        status_bar = ttk.Label(
            self.root, textvariable=self.status_var,
            relief=tk.SUNKEN, anchor=tk.W, padding=10
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def criar_aba_criptografia(self):
        container = ttk.Frame(self.aba_cripto)
        container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Seção de imagem
        file_frame = ttk.LabelFrame(container, text=" Imagem Chave ", padding=10)
        file_frame.pack(fill=tk.X, pady=5)
        
        self.entry_imagem_cripto = ttk.Entry(file_frame, state='readonly')
        self.entry_imagem_cripto.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(
            file_frame, text="Procurar", 
            command=lambda: self.selecionar_arquivo('cripto'),
            style='SecButton.TButton'
        ).pack(side=tk.RIGHT)
        
        # Seção de senha
        senha_frame = ttk.Frame(container)
        senha_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(senha_frame, text="Senha Adicional:").pack(side=tk.LEFT)
        
        self.senha_cripto = ttk.Entry(senha_frame, show="•")
        self.senha_cripto.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.btn_mostrar_senha_cripto = ttk.Button(
            senha_frame, text="👁️", width=3,
            command=lambda: self.mostrar_senha(self.senha_cripto),
            style='SecButton.TButton'
        )
        self.btn_mostrar_senha_cripto.pack(side=tk.RIGHT)
        
        # Área de texto com botões de ação
        text_frame = ttk.LabelFrame(container, text=" Texto Original ", padding=10)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        btn_frame = ttk.Frame(text_frame)
        btn_frame.pack(fill=tk.X, pady=5)
                
        ttk.Button(
            btn_frame, text="Copiar", 
            command=lambda: self.copiar_texto(self.texto_original),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame, text="Colar", 
            command=lambda: self.colar_texto(self.texto_original),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)

        ttk.Button(
            btn_frame, text="Limpar", 
            command=lambda: self.limpar_texto(self.texto_original),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        self.texto_original = tk.Text(text_frame, height=8, wrap=tk.WORD, font=('Helvetica', 10))
        self.texto_original.pack(fill=tk.BOTH, expand=True)
        
        # Botão principal
        ttk.Button(
            container, text="Criptografar", 
            command=self.executar_criptografia,
            style='Accent.TButton'
        ).pack(pady=10)
        
        # Resultado
        result_frame = ttk.LabelFrame(container, text=" Resultado Criptografado ", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        btn_frame_result = ttk.Frame(result_frame)
        btn_frame_result.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame_result, text="Copiar", 
            command=lambda: self.copiar_texto(self.texto_criptografado),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame_result, text="Limpar", 
            command=lambda: self.limpar_texto(self.texto_criptografado),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        self.texto_criptografado = tk.Text(
            result_frame, height=8, wrap=tk.WORD, 
            font=('Courier', 10), state='disabled')
        self.texto_criptografado.pack(fill=tk.BOTH, expand=True)

    def criar_aba_descriptografia(self):
        container = ttk.Frame(self.aba_descripto)
        container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Seção de imagem
        file_frame = ttk.LabelFrame(container, text=" Imagem Chave Original ", padding=10)
        file_frame.pack(fill=tk.X, pady=5)
        
        self.entry_imagem_descripto = ttk.Entry(file_frame, state='readonly')
        self.entry_imagem_descripto.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(
            file_frame, text="Procurar", 
            command=lambda: self.selecionar_arquivo('descripto'),
            style='SecButton.TButton'
        ).pack(side=tk.RIGHT)
        
        # Seção de senha
        senha_frame = ttk.Frame(container)
        senha_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(senha_frame, text="Senha Adicional:").pack(side=tk.LEFT)
        
        self.senha_descripto = ttk.Entry(senha_frame, show="•")
        self.senha_descripto.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.btn_mostrar_senha_descripto = ttk.Button(
            senha_frame, text="👁️", width=3,
            command=lambda: self.mostrar_senha(self.senha_descripto),
            style='SecButton.TButton'
        )
        self.btn_mostrar_senha_descripto.pack(side=tk.RIGHT)
        
        # Área de texto com botões de ação
        text_frame = ttk.LabelFrame(container, text=" Texto Criptografado ", padding=10)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        btn_frame = ttk.Frame(text_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame, text="Copiar", 
            command=lambda: self.copiar_texto(self.texto_para_descripto),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame, text="Colar", 
            command=lambda: self.colar_texto(self.texto_para_descripto),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame, text="Limpar", 
            command=lambda: self.limpar_texto(self.texto_para_descripto),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        self.texto_para_descripto = tk.Text(text_frame, height=8, wrap=tk.WORD, font=('Courier', 10))
        self.texto_para_descripto.pack(fill=tk.BOTH, expand=True)
        
        # Botão principal
        ttk.Button(
            container, text="Descriptografar", 
            command=self.executar_descriptografia,
            style='Accent.TButton'
        ).pack(pady=10)
        
        # Resultado
        result_frame = ttk.LabelFrame(container, text=" Texto Original ", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        btn_frame_result = ttk.Frame(result_frame)
        btn_frame_result.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame_result, text="Copiar", 
            command=lambda: self.copiar_texto(self.texto_descriptografado),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame_result, text="Limpar", 
            command=lambda: self.limpar_texto(self.texto_descriptografado),
            style='SecButton.TButton'
        ).pack(side=tk.LEFT, padx=2)
        
        self.texto_descriptografado = tk.Text(
            result_frame, height=8, wrap=tk.WORD, 
            font=('Helvetica', 10), state='disabled')
        self.texto_descriptografado.pack(fill=tk.BOTH, expand=True)

    def mostrar_senha(self, campo_senha):
        if campo_senha['show'] == '':
            campo_senha.config(show='•')
        else:
            campo_senha.config(show='')
        
        # Explicitamente sincroniza o botão de texto com o estado atual
        if campo_senha == self.senha_cripto:
            self.btn_mostrar_senha_cripto.config(text="👁️" if campo_senha['show'] == '•' else "🙈")
        elif campo_senha == self.senha_descripto:
            self.btn_mostrar_senha_descripto.config(text="👁️" if campo_senha['show'] == '•' else "🙈")

    def validar_entrada_criptografia(self, texto, senha):
        if len(texto) > self.MAX_TEXT_SIZE:
            raise ValueError("Texto muito grande para criptografar")
        if not texto.strip():
            raise ValueError("Texto não pode estar vazio")
        if not senha:
            raise ValueError("Senha não pode estar vazia")
        if len(senha) < 8:
            raise ValueError("Senha muito curta (mínimo 8 caracteres)")
 
    def copiar_texto(self, widget):
        texto = widget.get("1.0", tk.END).strip()
        if texto:
            self.root.clipboard_clear()
            self.root.clipboard_append(texto)
            self.status_var.set("Texto copiado para a área de transferência!")
            self.root.after(3000, lambda: self.status_var.set("Pronto para operações de criptografia"))

    def colar_texto(self, widget):
        try:
            texto = self.root.clipboard_get()
            if widget.cget('state') == 'disabled':
                widget.config(state='normal')
                widget.delete("1.0", tk.END)
                widget.insert("1.0", texto)
                widget.config(state='disabled')
            else:
                widget.delete("1.0", tk.END)
                widget.insert("1.0", texto)
            self.status_var.set("Texto colado com sucesso!")
            self.root.after(3000, lambda: self.status_var.set("Pronto para operações de criptografia"))
        except tk.TclError:
            messagebox.showwarning("Aviso", "Nenhum texto disponível para colar!")

    def limpar_texto(self, widget):
        if widget.cget('state') == 'disabled':
            widget.config(state='normal')
            widget.delete("1.0", tk.END)
            widget.config(state='disabled')
        else:
            widget.delete("1.0", tk.END)
        self.status_var.set("Área de texto limpa")
        self.root.after(3000, lambda: self.status_var.set("Pronto para operações de criptografia"))
        
    def selecionar_arquivo(self, tipo):
        try:
            arquivo = filedialog.askopenfilename(
                title="Selecione a imagem chave",
                filetypes=[("Imagens", "*.png *.jpg *.jpeg *.bmp")]
            )
            if arquivo:
                tamanho = Path(arquivo).stat().st_size
                if tamanho < self.tamanho_minimo:
                    raise ValueError(f"Imagem muito pequena (mínimo {self.tamanho_minimo} bytes)")
                
                if tipo == 'cripto':
                    self.arquivo_cripto = arquivo
                    self.entry_imagem_cripto.config(state='normal')
                    self.entry_imagem_cripto.delete(0, tk.END)
                    self.entry_imagem_cripto.insert(0, Path(arquivo).name)
                    self.entry_imagem_cripto.config(state='readonly')
                else:
                    self.arquivo_descripto = arquivo
                    self.entry_imagem_descripto.config(state='normal')
                    self.entry_imagem_descripto.delete(0, tk.END)
                    self.entry_imagem_descripto.insert(0, Path(arquivo).name)
                    self.entry_imagem_descripto.config(state='readonly')
                
                self.status_var.set(f"Imagem carregada: {Path(arquivo).name}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar imagem:\n{str(e)}")

    def gerar_chave_hibrida(self, conteudo_imagem, senha, salt):
        """
        Combina a imagem e senha para gerar chave híbrida.

        Parameters:
        conteudo_imagem (bytes): Conteúdo binário da imagem chave.
        senha (str): Senha adicional fornecida pelo usuário.
        salt (bytes): Salt aleatório usado para derivação da chave.
        kdf_iter: self.iteracoes_kdf
        algoritmo: 'AES-256-CBC-HMAC-BLAKE3'
        hmac_tamanho: 32

        Returns:
        bytes: Chave híbrida derivada.
        """
        # Calcula hash de todo o conteúdo da imagem
        hasher = blake3.blake3()
        chunk_size = 65536  # 64KB por chunk
        
        if isinstance(conteudo_imagem, (str, bytes)):
            hasher.update(conteudo_imagem if isinstance(conteudo_imagem, bytes) 
                          else conteudo_imagem.encode())
        else:  # Se for um arquivo grande
            conteudo_imagem.seek(0)
            while True:
                chunk = conteudo_imagem.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    
        hash_imagem = hasher.digest()
        hash_senha = blake3.blake3(senha.encode()).digest()
        material_chave = hash_senha + hash_imagem + salt
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=self.iteracoes_kdf,
            backend=default_backend()
        )
        pass
        return kdf.derive(material_chave)

    def criptografar_hibrido(self, texto, arquivo_imagem, senha):
        """Criptografia híbrida em duas camadas"""
        
        # Verificação de entrada
        self.validar_entrada_criptografia (texto, senha)

        with open(arquivo_imagem, 'rb') as f:
            conteudo_imagem = f.read()
        
        # Camada 1: Criptografia baseada em imagem
        iv = secrets.token_bytes(self.tamanho_iv)
        salt = secrets.token_bytes(self.tamanho_salt)
        
        # Gera chave híbrida
        chave = self.gerar_chave_hibrida(conteudo_imagem, senha, salt)
        
        # Camada 2: AES-256-CBC
        padder = padding.PKCS7(128).padder()
        texto_padded = padder.update(texto.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        texto_cifrado = encryptor.update(texto_padded) + encryptor.finalize()
        
        # HMAC para autenticação com Blake3 (32 bytes/256 bits)
        hmac = blake3.blake3(
            salt + iv + texto_cifrado,
            key=chave
        ).digest(length=32)

        # Pacote final
        return {
            'salt': base64.urlsafe_b64encode(salt).decode(),
            'iv': base64.urlsafe_b64encode(iv).decode(),
            'hmac': base64.urlsafe_b64encode(hmac).decode(),
            'cifrado': base64.urlsafe_b64encode(texto_cifrado).decode(),
        }

    def descriptografar_hibrido(self, pacote_cripto, arquivo_imagem, senha):
        """Descriptografia híbrida em duas camadas"""

        pacote = json.loads(pacote_cripto)
        
        # Decodifica componentes
        salt = base64.urlsafe_b64decode(pacote['salt'].encode())
        iv = base64.urlsafe_b64decode(pacote['iv'].encode())
        texto_cifrado = base64.urlsafe_b64decode(pacote['cifrado'].encode())
        hmac_recebido = base64.urlsafe_b64decode(pacote['hmac'].encode())
        
        with open(arquivo_imagem, 'rb') as f:
            conteudo_imagem = f.read()
        
        # Regenera a chave
        chave = self.gerar_chave_hibrida(conteudo_imagem, senha, salt)
        
        # Verifica HMAC
        hmac_calculado = blake3.blake3(
            salt + iv + texto_cifrado,
            key=chave
        ).digest(length=32)
        
        if not secrets.compare_digest(hmac_recebido, hmac_calculado):
            raise ValueError("Autenticação falhou - dados corrompidos ou credenciais inválidas")
        
        # Descriptografia AES
        cipher = Cipher(algorithms.AES(chave), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        texto_padded = decryptor.update(texto_cifrado) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()

        return unpadder.update(texto_padded) + unpadder.finalize()

    def executar_criptografia(self):
        self.ui_state.disable_ui()
        try:
            texto = self.texto_original.get("1.0", tk.END).strip()
            with SecureString(self.senha_cripto.get()) as senha_secure:
                self.validar_entrada_criptografia(texto, senha_secure.get())
                pacote = self.criptografar_hibrido(texto, self.arquivo_cripto, senha_secure.get())
                
            resultado = json.dumps(pacote, indent=2)
                
            if not hasattr(self, 'arquivo_cripto'):
                messagebox.showerror("Erro", "Selecione uma imagem chave primeiro!")
                return
            
            if not os.path.exists(self.arquivo_cripto):
                messagebox.showerror("Erro", "O arquivo de imagem chave não existe ou não está acessível!")
                return
            
            texto = self.texto_original.get("1.0", tk.END).strip()
            if not texto:
                messagebox.showerror("Erro", "Digite um texto para criptografar!")
                return
            
            #Protege a senha dentro da memória
            senha_secure = SecureString(self.senha_cripto.get())
            try:
                senha = self.senha_cripto.get()
            finally:
                senha_secure.clear()

            if not senha:
                messagebox.showerror("Erro", "Digite uma senha adicional!")
                return
            
            pacote = self.criptografar_hibrido(texto, self.arquivo_cripto, senha)
            resultado = json.dumps(pacote, indent=2)
            
            self.texto_criptografado.config(state='normal')
            self.texto_criptografado.delete("1.0", tk.END)
            self.texto_criptografado.insert("1.0", resultado)
            self.texto_criptografado.config(state='disabled')
            
            self.status_var.set("Criptografia concluída com sucesso!")

           
        except ValueError as e:
            messagebox.showerror("Erro", str(e))
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na criptografia: {str(e)}")

        finally:
            self.ui_state.enable_ui()

    def executar_descriptografia(self):
        try:
            if not hasattr(self, 'arquivo_descripto'):
                messagebox.showerror("Erro", "Selecione a imagem chave original!")
                return
            
            texto_cripto = self.texto_para_descripto.get("1.0", tk.END).strip()
            if not texto_cripto:
                messagebox.showerror("Erro", "Digite o texto criptografado!")
                return
            
            senha = self.senha_descripto.get()
            if not senha:
                messagebox.showerror("Erro", "Digite a senha adicional!")
                return
            
            texto = self.descriptografar_hibrido(texto_cripto, self.arquivo_descripto, senha)
            
            self.texto_descriptografado.config(state='normal')
            self.texto_descriptografado.delete("1.0", tk.END)
            self.texto_descriptografado.insert("1.0", texto)
            self.texto_descriptografado.config(state='disabled')
            
            self.status_var.set("Descriptografia concluída com sucesso!")
            
        except json.JSONDecodeError:
            messagebox.showerror("Erro", "Formato inválido do pacote criptografado")
        except ValueError as e:
            if "Autenticação falhou" in str(e):
                messagebox.showerror("Erro", "Falha na autenticação - credenciais inválidas")
            else:
                messagebox.showerror("Erro", "Ocorreu um erro durante a descriptografia")
        except Exception:
            messagebox.showerror("Erro", "Falha crítica durante a descriptografia")
            # Logar o erro real para diagnóstico interno

if __name__ == "__main__":
    root = tk.Tk()
    app = CriptografiaHibrida(root)
    root.mainloop()