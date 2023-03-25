from tkinter import BOTTOM, IntVar, StringVar
import customtkinter as ct
import tkinter.messagebox as tkmb
import tkinter as tk
from tkinter.filedialog import askdirectory, askopenfilename
import PyPDF2
import pyshark
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy
from fpdf import FPDF
from pydub import AudioSegment
import speech_recognition as sr
import os
from PIL import Image
ct.set_appearance_mode("dark")
ct.set_default_color_theme("dark-blue")

class voip_analyze:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        # self.report_path = report_path
        self.filtered_cap_tcp = pyshark.FileCapture(self.pcap_path, display_filter="tcp")
        self.filtered_cap_udp = pyshark.FileCapture(self.pcap_path, display_filter="udp")
        self.filtered_cap_sip = pyshark.FileCapture(self.pcap_path, display_filter="sip")
        self.filtered_cap_sdp = pyshark.FileCapture(self.pcap_path, display_filter="sdp")
        self.filtered_cap_rtp = pyshark.FileCapture(self.pcap_path, display_filter="rtp")
        self.filtered_cap_rtcp = pyshark.FileCapture(self.pcap_path, display_filter="rtcp")
        self.filtered_cap_tls = pyshark.FileCapture(self.pcap_path, display_filter="tls")


    def pie_chart1(self):
        self.filtered_cap_tcp.load_packets()
        self.filtered_cap_udp.load_packets()
        with PdfPages('report1.pdf') as pdf:
            no_of_tcp,no_of_udp = len(self.filtered_cap_tcp),len(self.filtered_cap_udp)
            list_of_types = {'TCP':no_of_tcp,'UDP':no_of_udp}
            lsizes= []
            labels=[]
            explode =[]
            for label,size in list_of_types.items():
                if size != 0:
                    lsizes.append(size)
                    labels.append(label)
                    explode.append(0)
            fig,ax = plt.subplots()
            ax.pie(lsizes, explode=explode, labels=labels, autopct='%1.1f%%',shadow=True, startangle=90)
            plt.title("TCP/UDP PACKET COMPOSITION CHART",loc="center")
            pdf.savefig()
            plt.close()        
    def pie_chart2(self):
        self.filtered_cap_sip.load_packets()
        self.filtered_cap_sdp.load_packets()
        self.filtered_cap_rtp.load_packets()
        self.filtered_cap_rtcp.load_packets()
        self.filtered_cap_tls.load_packets()
        global no_of_sip,no_of_sdp,no_of_rtp,no_of_rtcp,no_of_tls
        no_of_sip,no_of_sdp,no_of_rtp,no_of_rtcp,no_of_tls = len(self.filtered_cap_sip),len(self.filtered_cap_sdp),len(self.filtered_cap_rtp),len(self.filtered_cap_rtcp),len(self.filtered_cap_tls)
        with PdfPages('report2.pdf') as pdf:
            list_of_types = {'SIP':no_of_sip,'SDP':no_of_sdp,'RTP':no_of_rtp,'RTCP':no_of_rtcp,'TLS':no_of_tls}
            lsizes= []
            labels=[]
            explode =[]
            for label,size in list_of_types.items():
                if size != 0:
                    lsizes.append(size)
                    labels.append(label)
                    explode.append(0)
            fig,ax = plt.subplots()
            ax.pie(lsizes, explode=explode, labels=labels, autopct='%1.1f%%',
            shadow=True, startangle=90)
            plt.title("VOIP PACKET COMPOSITION CHART",loc="center")
            pdf.savefig()
            plt.close()
    def capture_sip_data(self):
        output = ""
        j=0
        for packet in self.filtered_cap_sip:
            try:
                content_type = packet.sip.content_type
            except:
                content_type = None
            try:
                to_tag = packet.sip.to_tag
            except:
                to_tag = None
            try:
                sip_user_agent = packet.sip.user_agent
            except:
                sip_user_agent = None
            try:
                sdp_session_name = packet.sip.sdp_session_name
                sdp_present = 1
                try:
                    sdp_media_proc = packet.sip.sdp_media_proto
                except:
                    sdp_media_proc = None
                try:
                    sdp_media_attr = packet.sip.sdp_media_attr
                except:
                    sdp_media_attr = None
                try:
                    sdp_media_format = packet.sip.sdp_media_format
                except:
                    sdp_media_format = None
                try:
                    sdp_media_port = packet.sip.sdp_media_port
                except:
                    sdp_media_port = None
                try:
                    sdp_fmtp_parameter = packet.sip.sdp_fmtp_parameter
                except:
                    sdp_fmtp_parameter = None
            except:
                sdp_present = 0
            try:
                packet_length = packet.length
            except:
                packet_length = None
            try:
                packet_method = packet.sip.cseq
            except:
                packet_method = None
            try:
                sip_call_id = packet.sip.call_id
            except:
                sip_call_id = None
            try:
                interface_name = packet.frame_info.interface_name
            except:
                interface_name = None
            try:
                highest_layer = packet.highest_layer
            except:
                highest_layer = None
            try:
                sip_from_user= packet.sip.from_user
            except:
                sip_from_user = None            
            try:
                source_ip = packet['ip'].src
            except:
                source_ip = None
            try:
                UDP_source_port = packet.udp.srcport
            except:
                UDP_source_port = None
            try:
                mac_source = packet['eth'].src
            except:
                mac_source = None
            try:
                sip_from_tag = packet.sip.from_tag
            except:
                sip_from_tag = None
            try:
                destination_ip = packet['ip'].dst
            except:
                destination_ip = None
            try:
                mac_destination = packet['eth'].dst
            except:
                mac_destination = None  
            try:
                UDP_dest_port = packet.udp.dstport     
            except:
                UDP_dest_port = None   
            try:
                ttl = packet['ip'].ttl
            except:
                ttl = None              
            try:
                frame_time = packet.frame_info.time
            except:
                frame_time = None   
            try:
                sniffed_timestamp = packet.sniff_timestamp
            except:
                sniffed_timestamp = None     
            if sdp_present==1:
                output += f"{j}. | {highest_layer} | {interface_name}: | FROM User: {sip_from_user}@{source_ip} PORT:{UDP_source_port} MAC:{mac_source}  Tag:{sip_from_tag} | TO | {destination_ip} MAC:{mac_destination} PORT:{UDP_dest_port} Tag:{to_tag} | {frame_time} | Sniffed_timestamp:{sniffed_timestamp} | Call_ID: {sip_call_id} | TTL: {ttl} | Packet_Length:{packet_length} | Method:{packet_method} | Content-type:{content_type} | User_Agent:{sip_user_agent}   SDP Info: Session_Name:{sdp_session_name} | Protocol:{sdp_media_proc} | Media_Attribute:{sdp_media_attr} | Media_format:{sdp_media_format} | Media_port:{sdp_media_port} | FMTP_parameter:{sdp_fmtp_parameter}\n"
                j+=1
            else:
                output += f"{j}. | {highest_layer} | {interface_name}: | FROM User: {sip_from_user}@{source_ip} PORT:{UDP_source_port} MAC:{mac_source}  Tag:{sip_from_tag} | TO | {destination_ip} MAC:{mac_destination} PORT:{UDP_dest_port} Tag:{to_tag} | {frame_time} | Sniffed_timestamp:{sniffed_timestamp} | Call_ID: {sip_call_id} | TTL: {ttl} | Packet_Length:{packet_length} | Method:{packet_method} | Content-type:{content_type} | User_Agent:{sip_user_agent}\n"
                j+=1
        pdf = FPDF(format="legal",orientation="landscape")
        pdf.add_page()
        pdf.set_font("Arial",size=6)
        pdf.multi_cell(w=0,txt="VoIP PACKET TRACE REPORT",border=1,h=4)
        pdf.multi_cell(w=0,txt =output,border=1,h=4)
        pdf.output("report3.pdf")
    def duration_of_call(self):
        count_invite = 0
        output = ""
        sender_ip = ''
        receiver_ip = ''
        for packet in self.filtered_cap_sip:
            if(packet.sip.cseq_method == 'INVITE' and packet.sip.field_names[0] != 'status_line' and packet.ip.src != sender_ip and packet.ip.dst != receiver_ip):
                count_invite += 1
                sender_ip = packet.ip.src
                receiver_ip = packet.ip.dst
                start_time = packet.frame_info.time_relative #packet.udp.time_relative 
                new_cap = pyshark.FileCapture(self.pcap_path, display_filter=f"sip && ip.src == {sender_ip} && ip.dst == {receiver_ip}")
                new_cap.load_packets()
                for packet in new_cap:
                    if(packet.sip.cseq_method == 'BYE'):
                        stop_time = packet.frame_info.time_relative
                total_time = float(stop_time) - float(start_time)
                output += f"Packet stream from {sender_ip} to {receiver_ip} has a call duration of {total_time} ==> START: {start_time} and STOP: {stop_time}\n"
        pdf = FPDF(format="legal",orientation="landscape")
        pdf.add_page()
        pdf.set_font("Arial",size=12)
        pdf.multi_cell(w=0,txt="CALL DURATION REPORT",border=1,h=10)
        pdf.multi_cell(w=0,txt =output,border=1,h=10)
        pdf.output("report4.pdf")                 
    def report_merge(self,check1,check2,check3,check4):
        files = []
        print(check1,check2,check3,check4)
        if(check1==1):
            files.append('report1.pdf')
        if(check2==1):
            files.append('report2.pdf')
        if(check3==1):
            files.append('report3.pdf')
        if(check4==1):
            files.append('report4.pdf')                                
        pdfMerge = PyPDF2.PdfMerger()
        if(len(files)>0):
            for file in files:
                pdfFile=open(file,'rb')
                pdfReader = PyPDF2.PdfReader(pdfFile)
                pdfMerge.append(pdfReader)
            pdfFile.close()
            pdfMerge.write('finalreport.pdf')
    def rtp_to_raw(self):
        rtp_list = []  
        raw_audio = open('Audio_database/raw_audio/report.raw','wb')
        for i in self.filtered_cap_rtp:
            try:
                rtp = i[3]
                if rtp.payload:
                    rtp_list.append(rtp.payload.split(":"))
            except:
                pass
        for rtp_packet in rtp_list:
            packet = " ".join(rtp_packet)
            audio = bytearray.fromhex(packet)
            raw_audio.write(audio)
    def raw_to_wav(self):
        try:
            p_type = self.filtered_cap_rtp[0].rtp.p_type.showname
            if (p_type.find('PCMU') != 1):
                os.system("sox -t ul -r 8000 -c 1 Audio_database/raw_audio/report.raw Audio_database/wav_audio/report.wav")
            elif (p_type.find('GSM') != 1):
                os.system("sox -t gsm -r 8000 -c 1 Audio_database/raw_audio/report.raw Audio_database/wav_audio/report.wav")
            elif (p_type.find('PCMA')!= 1):
                os.system("sox -t al -r 8000 -c 1 Audio_database/raw_audio/report.raw Audio_database/wav_audio/report.wav")        
            elif (p_type.find('G722')!= 1):
                os.fsencode("Audio_database/raw_audio/report.raw Audio_database/wav_audio/report.wav")
            elif (p_type.find('G729')!= 1):
                os.fsencode("-l mod_com_g729 Audio_database/raw_audio/report.raw Audio_database/wav_audio/report.wav")
            else:
                print("Codec unidentified.")
        except:
            pass
    # def srtp_decrypt(self):
    #     if (no_of_srtp != 0):
    #         key = '123'
    #         ip=''
    #         pcap_file = pyshark.FileCapture('self.filtered_cap_rtp', display_filter=f"srtp && ip.src == {ip}")
    #         try:
    #             #filtered cap for single rtp stream
    #             os.system(f"./tools//libsrtp/test/rtp_decoder -a -t 10 -e 256 -k {key} * < {pcap_file} | tools/text2pcap -t \"%M:%S.\" -u 10000,10000 - - > decrypted_rtp/report.pcap")
    #         except:
    #             pass
        #./rtp_decoder -a -t 10 -e 256 -k {key} * < {pcap_file} 
        #then use text2pcap
        #text2pcap -t "%M:%S." -u 10000,10000 - - > ./Normal_Call_two_parties_Decrypted.pcap
        

        #./srtp-decrypt -k <key> < normal_call_2_parties.pcap > decoded.raw
        #then import from hex dump in wireshark.
 
    def tls_decrypt(self):
        #/etc/asterisk/keys/default.key
        #/edit/preferences/protocol/ssl
        key = ''


    def any_rtp_message(self):
        mess = ''


    #srtp key in SIP/SDP decrypted packet (inline)


    #pcap2wav online service to convert to wav [includes offline script]
    def clean(self):
        try:
            os.system("rm Audio_database/raw_audio/* && rm charts/* && rm duration_report/* && rm sip_reports/* && rm uploaded_files/*")
        except:
            pass
            
            
    

    
    # def aud_to_text(self):
    #     # convert mp3 file to wav                                                       
    #     #sound = AudioSegment.from_wav("Audio_database/wav_audio/report.wav")
    #     # sound.export("transcript.wav", format="wav")


    #     # transcribe audio file                                                         
    #     AUDIO_FILE = "/home/gpi/Music/nsa_st.wav"

    #     # use the audio file as the audio source                                        
    #     r = sr.Recognizer()
    #     with sr.AudioFile(AUDIO_FILE) as source:
    #             audio = r.record(source)  # read the entire audio file                  
    #             print("Transcription: " + r.recognize_google(audio))
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-SRTP-Normal_Call_two_parties.pcap').pie_chart1()       
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-SRTP-Normal_Call_two_parties.pcap').pie_chart2()
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-RTP-Normal_Call_two_parties.pcap').capture_sip_data()
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-RTP-Normal_Call_two_parties.pcap').duration_of_call()
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-RTP-Normal_Call_two_parties.pcap').report_merge()
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-RTP-Normal_Call_two_parties.pcap').rtp_to_raw()
# voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-RTP-Normal_Call_two_parties.pcap').raw_to_wav()
#voip_analyze('/home/gpi/TNhackathon/voipshark/Sample PCAPs/SIP-RTP-Normal_Call_two_parties.pcap').aud_to_text()


    # voip_analyze(path).rtp_to_raw()
    # voip_analyze(path).raw_to_wav()
    # voip_analyze(path).aud_to_text()




    

def login():

    def validateLogin():
        if(username_entry.get() == 'Gifton' and password_entry.get() == "Pass"):
            user_name_str = username_entry.get()
            login_window.destroy()
            #page(user_name_str)
        else:
            tkmb.showerror(title="Login Failed",message="Invalid Username and password")
    login_window = ct.CTk()
    login_window.geometry("500x350")
    login_window.title("Login")
    frame = ct.CTkFrame(master=login_window)
    frame.pack(pady=20,padx=60,fill="both",expand=True)
    label = ct.CTkLabel(master=frame, text="Network Shark")
    label.pack(pady=12,padx=10)
    username_entry = ct.CTkEntry(master=frame,placeholder_text="Username")
    username_entry.pack(pady=12,padx=10)
    password_entry = ct.CTkEntry(master=frame,placeholder_text="Password",show="*")
    password_entry.pack(pady=12,padx=10)
    button = ct.CTkButton(master=frame, text="Login",command=validateLogin)
    button.pack(pady=12,padx=10)
    checkbox = ct.CTkCheckBox(master=frame, text="Show Password")
    checkbox.pack(pady=12,padx=10)
    login_window.mainloop()


def dashboard(username):
    def analyze_page():
        dashboard.destroy()
        #page(username)

    def change_password():
        k = 1
    dashboard = ct.CTk()
    dashboard.geometry("700x450")
    dashboard.title("Dashboard")
    edit_frame1 = ct.CTkFrame(master=dashboard)
    edit_frame1.pack(padx=20,pady=20,fill=ct.BOTH, expand=True,side=ct.LEFT)
    


    analyze_btn = ct.CTkButton(master=edit_frame1,text="Analyze voip captures",command=analyze_page)
    analyze_btn.pack()


    profile_frame = ct.CTkFrame(master=dashboard)
    profile_frame.pack(padx=20,pady=20,fill=ct.BOTH, expand=True,side=ct.RIGHT)
    edit_frame2 = ct.CTkFrame(master=dashboard)
    edit_frame2.pack(padx=20,pady=20, expand=True,fill=ct.BOTH,side=ct.BOTTOM)

    welcome = ct.CTkLabel(padx=20,pady=20,master=edit_frame2,text=f"Welcome {username}!")
    welcome.pack()
    change_pass_btn = ct.CTkButton(master=edit_frame2,text="Change password",command=change_password)
    change_pass_btn.pack()
    edit_frame3 = ct.CTkFrame(master=dashboard)
    edit_frame3.pack(padx=20,pady=20, expand=False,side=ct.BOTTOM)
    logo = ct.CTkImage(light_image=Image.open("./logo/logo.png"),dark_image=Image.open("./logo/logo.png"),size=(150,150))
    logo_but = ct.CTkButton(master=edit_frame3,image=logo,fg_color="#1A1A1A",text="",hover=False)
    logo_but.pack()

    dashboard.mainloop()
#login()
#232223
#dashboard("Gifton")






















class App(ct.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Shark")
        self.geometry("1100x760")
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_images")
        self.icon = tk.PhotoImage(file = os.path.join(image_path,"logo.png"))
        self.iconphoto(False,self.icon)
        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # load images with light and dark mode image
        
        self.logo_image = ct.CTkImage(Image.open(os.path.join(image_path, "logo1.png")), size=(26, 26))
        self.large_test_image = ct.CTkImage(Image.open(os.path.join(image_path, "large_test_image.png")), size=(500, 150))
        self.image_icon_image = ct.CTkImage(Image.open(os.path.join(image_path, "image_icon_light.png")), size=(20, 20))
        self.home_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "home_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "home_light.png")), size=(20, 20))
        self.chat_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "chat_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "chat_light.png")), size=(20, 20))
        self.add_user_image = ct.CTkImage(light_image=Image.open(os.path.join(image_path, "add_user_dark.png")),
                                                     dark_image=Image.open(os.path.join(image_path, "add_user_light.png")), size=(20, 20))

        # create navigation frame
        self.navigation_frame = ct.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(4, weight=1)

        self.navigation_frame_label = ct.CTkLabel(self.navigation_frame, text="  Network Shark", image=self.logo_image,
                                                             compound="left", font=ct.CTkFont(size=15, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Home",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.home_image, anchor="w", command=self.home_button_event)
        self.home_button.grid(row=1, column=0, sticky="ew")

        self.frame_2_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Frame 2",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.chat_image, anchor="w", command=self.frame_2_button_event)
        self.frame_2_button.grid(row=2, column=0, sticky="ew")

        self.frame_3_button = ct.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Frame 3",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.add_user_image, anchor="w", command=self.frame_3_button_event)
        self.frame_3_button.grid(row=3, column=0, sticky="ew")

        self.appearance_mode_menu = ct.CTkOptionMenu(self.navigation_frame, values=["Light", "Dark", "System"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=6, column=0, padx=20, pady=20, sticky="s")

        # create home frame
        self.home_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)

        self.home_frame_large_image_label = ct.CTkLabel(self.home_frame, text="", image=self.large_test_image)
        self.home_frame_large_image_label.grid(row=0, column=0, padx=20, pady=10)

        # self.home_frame_button_1 = ct.CTkButton(self.home_frame, text="", image=self.image_icon_image)
        # self.home_frame_button_1.grid(row=1, column=0, padx=20, pady=10)
        # self.home_frame_button_2 = ct.CTkButton(self.home_frame, text="CTkButton", image=self.image_icon_image, compound="right")
        # self.home_frame_button_2.grid(row=2, column=0, padx=20, pady=10)
        # self.home_frame_button_3 = ct.CTkButton(self.home_frame, text="CTkButton", image=self.image_icon_image, compound="top")
        # self.home_frame_button_3.grid(row=3, column=0, padx=20, pady=10)
        # self.home_frame_button_4 = ct.CTkButton(self.home_frame, text="CTkButton", image=self.image_icon_image, compound="bottom", anchor="w")
        # self.home_frame_button_4.grid(row=4, column=0, padx=20, pady=10)
        
        
        # def new_page():
        #     self.home_frame.
        
        def open_pcap():            
                filename = askopenfilename(initialdir="/", title="Select the capture file",filetypes=(('Pcap Files','*.pcap'),('Pcapng files','*.pcapng')))
                pcap_file_label.configure(text="File Opened: "+filename)
                pcap_path = filename
                # self.report_path = report_path
                filtered_cap_tcp = pyshark.FileCapture(pcap_path, display_filter="tcp")
                filtered_cap_udp = pyshark.FileCapture(pcap_path, display_filter="udp")
                filtered_cap_sip = pyshark.FileCapture(pcap_path, display_filter="sip")
                filtered_cap_sdp = pyshark.FileCapture(pcap_path, display_filter="sdp")
                filtered_cap_rtp = pyshark.FileCapture(pcap_path, display_filter="rtp")
                filtered_cap_rtcp = pyshark.FileCapture(pcap_path, display_filter="rtcp")
                filtered_cap_tls = pyshark.FileCapture(pcap_path, display_filter="tls")
                def run(pcap_path):
                    if(check_var1 ==0 and check_var1 == 0 and check_var2 == 0 and check_var3 == 0 and check_var4 == 0):
                        tkmb.showerror(title="Error",message="No options were selected")
                    else: 
                        case_name = case_entry.get()
                        def dest_window():
                            def open_dest():
                                directory = askdirectory()
                                dest_file_label.configure(text=f"Destination: {directory}")
                                success_label = ct.CTkLabel(master=dest_window,text="")
                                success_label.grid(row=2,column=0,padx=20,pady=10) 
                                try:
                                    os.system(f"mv cache_files/finalreport.pdf {directory}/{case_name}.pdf")
                                    success_label.configure(text="File saved in the destination")
                                    dest_window.lift()
                                    ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                    ok.grid(row=3,column=0,padx=20,pady=10) 
                                except:
                                    success_label.configure(text="Something went wrong! Try Again!")
                                    dest_window.lift()
                                    os.system("rm cache_files/finalreport.pdf")
                                    ok = ct.CTkButton(master=dest_window,text="Ok",command=lambda: dest_window.destroy())
                                    ok.grid(row=3,column=0,padx=20,pady=10)             
                            dest_window = ct.CTk()
                            dest_window.geometry("500x250")
                            dest_window.grid_columnconfigure(0, weight=1)
                            dest_window.lift()
                            dest_window.title("Specify Destination")
                            # icon = tk.PhotoImage(file = os.path.join(image_path,"logo.png"))
                            # dest_window.iconphoto(False,icon)
                            dest_file_label = ct.CTkLabel(master=dest_window,text="Please specify the destination folder to save the report.")
                            dest_file_btn = ct.CTkButton(master=dest_window, text ='Browse', command= open_dest)
                            dest_file_label.grid(row=0,column=0,padx=20,pady=10)
                            dest_file_btn.grid(row=1,column=0,padx=20,pady=10)                      
                        gen= ct.CTkLabel(master=self.home_frame,text=f"Generating...Please hold still...")
                        gen.grid(row=10, column=0, padx=20, pady=10)                    
                        bar = ct.CTkProgressBar(master=self.home_frame,width=500)
                        bar.grid(row=11, column=0, padx=20, pady=10)
                        def check_checkbuttom_vals():
                            val = 0
                            if(check_var1.get()):
                                filtered_cap_tcp.load_packets()
                                filtered_cap_udp.load_packets()
                                with PdfPages('cache_files/report1.pdf') as pdf:
                                    no_of_tcp,no_of_udp = len(filtered_cap_tcp),len(filtered_cap_udp)
                                    list_of_types = {'TCP':no_of_tcp,'UDP':no_of_udp}
                                    lsizes= []
                                    labels=[]
                                    explode =[]
                                    for label,size in list_of_types.items():
                                        if size != 0:
                                            lsizes.append(size)
                                            labels.append(label)
                                            explode.append(0)
                                    fig,ax = plt.subplots()
                                    ax.pie(lsizes, explode=explode, labels=labels, autopct='%1.1f%%',shadow=True, startangle=90)
                                    plt.title("TCP/UDP PACKET COMPOSITION CHART",loc="center")
                                    pdf.savefig()
                                    plt.close()  
                                val+=0.2  
                                bar.set(val)  
                                self.appearance_mode_menu.update_idletasks()
                                gen.configure(text="Ya it's generating....")
                            if(check_var2.get()):
                                filtered_cap_sip.load_packets()
                                filtered_cap_sdp.load_packets()
                                filtered_cap_rtp.load_packets()
                                filtered_cap_rtcp.load_packets()
                                filtered_cap_tls.load_packets()
                                global no_of_sip,no_of_sdp,no_of_rtp,no_of_rtcp,no_of_tls
                                no_of_sip,no_of_sdp,no_of_rtp,no_of_rtcp,no_of_tls = len(filtered_cap_sip),len(filtered_cap_sdp),len(filtered_cap_rtp),len(filtered_cap_rtcp),len(filtered_cap_tls)
                                with PdfPages('cache_files/report2.pdf') as pdf:
                                    list_of_types = {'SIP':no_of_sip,'SDP':no_of_sdp,'RTP':no_of_rtp,'RTCP':no_of_rtcp,'TLS':no_of_tls}
                                    lsizes= []
                                    labels=[]
                                    explode =[]
                                    for label,size in list_of_types.items():
                                        if size != 0:
                                            lsizes.append(size)
                                            labels.append(label)
                                            explode.append(0)
                                    fig,ax = plt.subplots()
                                    ax.pie(lsizes, explode=explode, labels=labels, autopct='%1.1f%%',
                                    shadow=True, startangle=90)
                                    plt.title("VOIP PACKET COMPOSITION CHART",loc="center")
                                    pdf.savefig()
                                    plt.close()
                                val+=0.2
                                bar.set(val)  
                                self.appearance_mode_menu.update_idletasks()
                                gen.configure(text="Have a sip of water...")
                            if(check_var3.get()):
                                output = ""
                                j=0
                                for packet in filtered_cap_sip:
                                    try:
                                        content_type = packet.sip.content_type
                                    except:
                                        content_type = None
                                    try:
                                        to_tag = packet.sip.to_tag
                                    except:
                                        to_tag = None
                                    try:
                                        sip_user_agent = packet.sip.user_agent
                                    except:
                                        sip_user_agent = None
                                    try:
                                        sdp_session_name = packet.sip.sdp_session_name
                                        sdp_present = 1
                                        try:
                                            sdp_media_proc = packet.sip.sdp_media_proto
                                        except:
                                            sdp_media_proc = None
                                        try:
                                            sdp_media_attr = packet.sip.sdp_media_attr
                                        except:
                                            sdp_media_attr = None
                                        try:
                                            sdp_media_format = packet.sip.sdp_media_format
                                        except:
                                            sdp_media_format = None
                                        try:
                                            sdp_media_port = packet.sip.sdp_media_port
                                        except:
                                            sdp_media_port = None
                                        try:
                                            sdp_fmtp_parameter = packet.sip.sdp_fmtp_parameter
                                        except:
                                            sdp_fmtp_parameter = None
                                    except:
                                        sdp_present = 0
                                    try:
                                        packet_length = packet.length
                                    except:
                                        packet_length = None
                                    try:
                                        packet_method = packet.sip.cseq
                                    except:
                                        packet_method = None
                                    try:
                                        sip_call_id = packet.sip.call_id
                                    except:
                                        sip_call_id = None
                                    try:
                                        interface_name = packet.frame_info.interface_name
                                    except:
                                        interface_name = None
                                    try:
                                        highest_layer = packet.highest_layer
                                    except:
                                        highest_layer = None
                                    try:
                                        sip_from_user= packet.sip.from_user
                                    except:
                                        sip_from_user = None            
                                    try:
                                        source_ip = packet['ip'].src
                                    except:
                                        source_ip = None
                                    try:
                                        UDP_source_port = packet.udp.srcport
                                    except:
                                        UDP_source_port = None
                                    try:
                                        mac_source = packet['eth'].src
                                    except:
                                        mac_source = None
                                    try:
                                        sip_from_tag = packet.sip.from_tag
                                    except:
                                        sip_from_tag = None
                                    try:
                                        destination_ip = packet['ip'].dst
                                    except:
                                        destination_ip = None
                                    try:
                                        mac_destination = packet['eth'].dst
                                    except:
                                        mac_destination = None  
                                    try:
                                        UDP_dest_port = packet.udp.dstport     
                                    except:
                                        UDP_dest_port = None   
                                    try:
                                        ttl = packet['ip'].ttl
                                    except:
                                        ttl = None              
                                    try:
                                        frame_time = packet.frame_info.time
                                    except:
                                        frame_time = None   
                                    try:
                                        sniffed_timestamp = packet.sniff_timestamp
                                    except:
                                        sniffed_timestamp = None     
                                    if sdp_present==1:
                                        output += f"{j}. | {highest_layer} | {interface_name}: | FROM User: {sip_from_user}@{source_ip} PORT:{UDP_source_port} MAC:{mac_source}  Tag:{sip_from_tag} | TO | {destination_ip} MAC:{mac_destination} PORT:{UDP_dest_port} Tag:{to_tag} | {frame_time} | Sniffed_timestamp:{sniffed_timestamp} | Call_ID: {sip_call_id} | TTL: {ttl} | Packet_Length:{packet_length} | Method:{packet_method} | Content-type:{content_type} | User_Agent:{sip_user_agent}   SDP Info: Session_Name:{sdp_session_name} | Protocol:{sdp_media_proc} | Media_Attribute:{sdp_media_attr} | Media_format:{sdp_media_format} | Media_port:{sdp_media_port} | FMTP_parameter:{sdp_fmtp_parameter}\n"
                                        j+=1
                                    else:
                                        output += f"{j}. | {highest_layer} | {interface_name}: | FROM User: {sip_from_user}@{source_ip} PORT:{UDP_source_port} MAC:{mac_source}  Tag:{sip_from_tag} | TO | {destination_ip} MAC:{mac_destination} PORT:{UDP_dest_port} Tag:{to_tag} | {frame_time} | Sniffed_timestamp:{sniffed_timestamp} | Call_ID: {sip_call_id} | TTL: {ttl} | Packet_Length:{packet_length} | Method:{packet_method} | Content-type:{content_type} | User_Agent:{sip_user_agent}\n"
                                        j+=1
                                pdf = FPDF(format="legal",orientation="landscape")
                                pdf.add_page()
                                pdf.set_font("Arial",size=6)
                                pdf.multi_cell(w=0,txt="VoIP PACKET TRACE REPORT",border=1,h=4)
                                pdf.multi_cell(w=0,txt =output,border=1,h=4)
                                pdf.output("cache_files/report3.pdf")
                                val+=0.2
                                bar.set(val)  
                                self.appearance_mode_menu.update_idletasks()
                                gen.configure(text="Be patient...")
                            if(check_var4.get()):
                                count_invite = 0
                                output = ""
                                sender_ip = ''
                                receiver_ip = ''
                                for packet in filtered_cap_sip:
                                    if(packet.sip.cseq_method == 'INVITE' and packet.sip.field_names[0] != 'status_line' and packet.ip.src != sender_ip and packet.ip.dst != receiver_ip):
                                        count_invite += 1
                                        sender_ip = packet.ip.src
                                        receiver_ip = packet.ip.dst
                                        start_time = packet.frame_info.time_relative #packet.udp.time_relative 
                                        new_cap = pyshark.FileCapture(pcap_path, display_filter=f"sip && ip.src == {sender_ip} && ip.dst == {receiver_ip}")
                                        new_cap.load_packets()
                                        for packet in new_cap:
                                            if(packet.sip.cseq_method == 'BYE'):
                                                stop_time = packet.frame_info.time_relative
                                        total_time = float(stop_time) - float(start_time)
                                        output += f"Packet stream from {sender_ip} to {receiver_ip} has a call duration of {total_time} ==> START: {start_time} and STOP: {stop_time}\n"
                                pdf = FPDF(format="legal",orientation="landscape")
                                pdf.add_page()
                                pdf.set_font("Arial",size=12)
                                pdf.multi_cell(w=0,txt="CALL DURATION REPORT",border=1,h=10)
                                pdf.multi_cell(w=0,txt =output,border=1,h=10)
                                pdf.output("cache_files/report4.pdf") 
                                val+=0.2
                                bar.set(val)  
                                self.appearance_mode_menu.update_idletasks()
                                gen.configure(text="Almost done...")
                            if(1):
                                files = []
                                print(check_var1.get(),check_var2.get(),check_var3.get(),check_var4.get())
                                if(check_var1.get()):
                                    files.append('cache_files/report1.pdf')
                                if(check_var2.get()):
                                    files.append('cache_files/report2.pdf')
                                if(check_var3.get()):
                                    files.append('cache_files/report3.pdf')
                                if(check_var4.get()):
                                    files.append('cache_files/report4.pdf')                                
                                pdfMerge = PyPDF2.PdfMerger()
                                if(len(files)>0):
                                    for file in files:
                                        pdfFile=open(file,'rb')
                                        pdfReader = PyPDF2.PdfReader(pdfFile)
                                        pdfMerge.append(pdfReader)
                                    pdfFile.close()
                                    pdfMerge.write('cache_files/finalreport.pdf')
                                finalval = 1
                                bar.set(finalval)
                                self.appearance_mode_menu.update_idletasks()
                                os.system("rm cache_files/report*.pdf")
                                #label to set that the file has been generated in the destination    
                                gen.configure(text="The PDF report has been generated.")
                                dest_window()
                        check_checkbuttom_vals()
                check_var1 = IntVar()
                check_var2 = IntVar()
                check_var3 = IntVar()
                check_var4 = IntVar()
                def checkbox_event():
                    print("checkbox toggled, current value:", check_var1.get())
                    print("checkbox toggled, current value:", check_var2.get())
                    print("checkbox toggled, current value:", check_var3.get())
                    print("checkbox toggled, current value:", check_var4.get())
                    print('/n')
                check_btn1 = ct.CTkCheckBox(master=self.home_frame, text = "TCP/UDP report",
                                        variable=check_var1,
                                        command=checkbox_event,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn1.grid(row=5, column=0, padx=20, pady=10)
                check_btn2 = ct.CTkCheckBox(master=self.home_frame, text = "Voip Packet Composition report",
                                        variable=check_var2,
                                        command=checkbox_event,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn2.grid(row=6, column=0, padx=20, pady=10)
                check_btn3 = ct.CTkCheckBox(master=self.home_frame, text = "SIP packet data report",
                                        variable=check_var3,
                                        command=checkbox_event,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn3.grid(row=7, column=0, padx=20, pady=10)
                check_btn4 = ct.CTkCheckBox(master=self.home_frame, text = "Duration of the call report",
                                        variable=check_var4,
                                        command=checkbox_event,
                                        onvalue=1,
                                        offvalue=0,
                                        height=2,
                                        width=10)
                check_btn4.grid(row=8, column=0, padx=20, pady=10)
                analyse_btn = ct.CTkButton(master=self.home_frame,text="Generate report",command=lambda: run(filename))
                analyse_btn.grid(row=9, column=0, padx=20, pady=10)

        case_label = ct.CTkLabel(master=self.home_frame,text="Please specify the case ID: [Avoid invalid symbols]")
        case_label.grid(row=1,column=0,padx=20,pady=10)
        case_entry = ct.CTkEntry(master=self.home_frame,placeholder_text="Case ID")
        case_entry.grid(row=2,column=0,padx=20,pady=10)
        pcap_file_label = ct.CTkLabel(master=self.home_frame,text="Specify the location of the PCAP file that you want to analyse",width=100,height=4)
        pcap_file_btn = ct.CTkButton(master=self.home_frame, text ='Open', command= open_pcap)
        pcap_file_label.grid(row=3, column=0, padx=20, pady=10)
        pcap_file_btn.grid(row=4, column=0, padx=20, pady=10)
        #repage = ct.CTkButton(master=self.home_frame,text="Back to Home",command=new_page,hover=True)
        #repage.pack(side=BOTTOM,padx=120,pady=10)   

        # create second frame
        self.second_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")


        # create third frame
        self.third_frame = ct.CTkFrame(self, corner_radius=0, fg_color="transparent")

        # select default frame
        self.select_frame_by_name("home")

    def select_frame_by_name(self, name):
        # set button color for selected button
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "home" else "transparent")
        self.frame_2_button.configure(fg_color=("gray75", "gray25") if name == "frame_2" else "transparent")
        self.frame_3_button.configure(fg_color=("gray75", "gray25") if name == "frame_3" else "transparent")

        # show selected frame
        if name == "home":
            self.home_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "frame_2":
            self.second_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.second_frame.grid_forget()
        if name == "frame_3":
            self.third_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.third_frame.grid_forget()

    def home_button_event(self):
        self.select_frame_by_name("home")

    def frame_2_button_event(self):
        self.select_frame_by_name("frame_2")

    def frame_3_button_event(self):
        self.select_frame_by_name("frame_3")

    def change_appearance_mode_event(self, new_appearance_mode):
        ct.set_appearance_mode(new_appearance_mode)

app = App()
app.mainloop()