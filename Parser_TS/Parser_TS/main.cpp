#include<stdio.h>
#include<memory.h>
#include<vector>
// Transport packet header
typedef struct TS_packet_header
{
	unsigned sync_byte : 8;    //同步字节，固定为0x47 ，表示后面的是一个TS分组，当然，后面包中的数据是不会出现0x47的
	unsigned transport_error_indicator : 1;      //传输错误标志位，一般传输错误的话就不会处理这个包了
	unsigned payload_unit_start_indicator : 1;      //有效负载的开始标志，根据后面有效负载的内容不同功能也不同
	unsigned transport_priority : 1;      //传输优先级位，1表示高优先级
	unsigned PID : 13;     //有效负载数据的类型
	unsigned transport_scrambling_control : 2;      //加密标志位,00表示未加密
	unsigned adaption_field_control : 2;      //调整字段控制,。01仅含有效负载，10仅含调整字段，11含有调整字段和有效负载。为00的话解码器不进行处理。
	unsigned continuity_counter : 4;    //一个4bit的计数器，范围0-15
} TS_packet_header;
typedef struct TS_PAT_Program
{
	unsigned  program_map_PID;
	unsigned  program_number;

}TS_PAT_Program;
//PAT表结构体
typedef struct TS_PAT
{
	unsigned table_id : 8; //固定为0x00 ，标志是该表是PAT
	unsigned section_syntax_indicator : 1; //段语法标志位，固定为1
	unsigned zero : 1; //0
	unsigned reserved_1 : 2; // 保留位
	unsigned section_length : 12; //表示这个字节后面有用的字节数，包括CRC32
	unsigned transport_stream_id : 16; //该传输流的ID，区别于一个网络中其它多路复用的流
	unsigned reserved_2 : 2;// 保留位
	unsigned version_number : 5; //范围0-31，表示PAT的版本号
	unsigned current_next_indicator : 1; //发送的PAT是当前有效还是下一个PAT有效
	unsigned section_number : 8; //分段的号码。PAT可能分为多段传输，第一段为00，以后每个分段加1，最多可能有256个分段
	unsigned last_section_number : 8;  //最后一个分段的号码

	std::vector<TS_PAT_Program> program;

	unsigned reserved_3 : 3; // 保留位
	unsigned network_PID : 13; //网络信息表（NIT）的PID,节目号为0时对应的PID为network_PID
	unsigned CRC_32 : 32;  //CRC32校验码

}TS_PAT;

typedef struct TS_PMT_Stream
{
	unsigned stream_type : 8; //指示特定PID的节目元素包的类型。该处PID由elementary PID指定
	unsigned elementary_PID : 13; //该域指示TS包的PID值。这些TS包含有相关的节目元素
	unsigned ES_info_length : 12; //前两位bit为00。该域指示跟随其后的描述相关节目元素的byte数
	unsigned descriptor;
}TS_PMT_Stream;
//PMT 表结构体
typedef struct TS_PMT
{
	unsigned table_id : 8; //固定为0x02, 表示PMT表
	unsigned section_syntax_indicator : 1; //固定为0x01
	unsigned zero : 1; //0x01
	unsigned reserved_1 : 2; //0x03
	unsigned section_length : 12;//首先两位bit置为00，它指示段的byte数，由段长度域开始，包含CRC。
	unsigned program_number : 16;// 指出该节目对应于可应用的Program map PID
	unsigned reserved_2 : 2; //0x03
	unsigned version_number : 5; //指出TS流中Program map section的版本号
	unsigned current_next_indicator : 1; //当该位置1时，当前传送的Program map section可用；
										 //当该位置0时，指示当前传送的Program map section不可用，下一个TS流的Program map section有效。
	unsigned section_number : 8; //固定为0x00
	unsigned last_section_number : 8; //固定为0x00
	unsigned reserved_3 : 3; //0x07
	unsigned PCR_PID : 13; //指明TS包的PID值，该TS包含有PCR域，
						   //该PCR值对应于由节目号指定的对应节目。
						   //如果对于私有数据流的节目定义与PCR无关，这个域的值将为0x1FFF。
	unsigned reserved_4 : 4; //预留为0x0F
	unsigned program_info_length : 12; //前两位bit为00。该域指出跟随其后对节目信息的描述的byte数。

	std::vector<TS_PMT_Stream> PMT_Stream;  //每个元素包含8位, 指示特定PID的节目元素包的类型。该处PID由elementary PID指定
	unsigned reserved_5 : 3; //0x07
	unsigned reserved_6 : 4; //0x0F
	unsigned CRC_32 : 32;
} TS_PMT;
//Adaptation
typedef struct TS_Adaptation
{
	unsigned adaptation_field_length : 8;//自适应字节长度
	unsigned discontinuity_indicator : 1;
	unsigned random_access_indicator : 1;
	unsigned elementary_stream_priority_indicator : 1;
	unsigned PCR_flag : 1;
	unsigned OPCR_flag : 1;
	unsigned splicing_point_flag : 1;
	unsigned transport_private_data_flag : 1;
	unsigned adaptation_field_extension_flag : 1;

	//unsigned program_clock_reference_base : 33;
	unsigned Reserved : 6;
	unsigned program_clock_reference_extension : 9;

}TS_Adaptation;
//PES结构体
typedef struct TS_PES
{
	unsigned packet_start_code_prefix : 24;//包的起始码 00 00 01
	unsigned stream_id : 8;				//流的类型和编号
	unsigned PES_packet_length : 16;	//PES包中字节总长度
	//默认2bit 10
	unsigned PES_scrambling_control : 2;	//加扰方式
	unsigned PES_priority : 1;	//有效载荷的优先级
	unsigned data_alignment_indicator : 1;
	unsigned copyright : 1;//有效载荷是否受版权保护
	unsigned original_or_copy : 1;//有效载荷数据是否是复制
	unsigned PTS_DTS_flags : 2;//PTS和DIS是否存在
	unsigned ESCR_flag : 1;//
	unsigned ES_rate_flag : 1;//
	unsigned DSM_trick_mode_flag : 1;//
	unsigned additional_copy_info_flag : 1;
	unsigned PES_CRC_flag : 1;
	unsigned PES_extension_flag : 1;
	unsigned PES_header_data_length : 8;//
	unsigned marker_bit : 1;

	unsigned long long PTS : 33;
	unsigned long long DTS : 33;
}TS_PES;

std::vector<TS_PAT_Program>TS_program;
std::vector<TS_PMT_Stream>TS_Stream_type;

unsigned int TS_network_Pid;
unsigned int PCRID;

void Func_Read_PES(unsigned char *buffer, TS_PES *packet)
{
	packet->packet_start_code_prefix = buffer[0] << 16 | buffer[1] << 8 | buffer[2] & 0xFFFFFF;
	packet->stream_id = buffer[3];
	packet->PES_packet_length = buffer[4] << 8 | buffer[5] & 0xFFFF;

	packet->PES_scrambling_control = buffer[6] >> 4 & 0x03;
	packet->PES_priority = buffer[6] >> 3 & 0x01;
	packet->data_alignment_indicator = buffer[6] >> 2 & 0x01;
	packet->copyright = buffer[6] >> 1 & 0x01;
	packet->original_or_copy = buffer[6] & 0x01;

	packet->PTS_DTS_flags = buffer[7] >> 6 & 0x03;
	packet->ESCR_flag = buffer[7] >> 5 & 0x01;
	packet->ES_rate_flag = buffer[7] >> 4 & 0x01;
	packet->DSM_trick_mode_flag = buffer[7] >> 3 & 0x01;
	packet->additional_copy_info_flag = buffer[7] >> 2 & 0x01;
	packet->PES_CRC_flag = buffer[7] >> 1 & 0x01;
	packet->PES_extension_flag = buffer[7] & 0x01;

	packet->PES_header_data_length = buffer[8];

	switch (packet->PTS_DTS_flags)
	{
	case 2://10 PTS
		packet->PTS = (((unsigned long long)(buffer[9]& 0x0E)) << 29)
				|(unsigned long long)(buffer[10]<< 22)
				|(((unsigned long long)(buffer[11]& 0xFE)) << 14)
				|(unsigned long long)(buffer[12]<< 7)
				|(unsigned long long)(buffer[13]>> 1);
		break;
	case 3://11 PTS DTS
		packet->PTS = (((unsigned long long)(buffer[9] & 0x0E)) << 29)
			| (unsigned long long)(buffer[10] << 22)
			| (((unsigned long long)(buffer[11] & 0xFE)) << 14)
			| (unsigned long long)(buffer[12] << 7)
			| (unsigned long long)(buffer[13] >> 1);

		packet->DTS = (((unsigned long long)(buffer[14] & 0x0E)) << 29)
			| (unsigned long long)(buffer[15] << 22)
			| (((unsigned long long)(buffer[16] & 0xFE)) << 14)
			| (unsigned long long)(buffer[17] << 7)
			| (unsigned long long)(buffer[18] >> 1);
		break;
	case 0://都没有
		break;
	case 1://禁止
		break;
	default:
		break;
	}
	if (packet->ESCR_flag == 1)
	{

	}
	if (packet->ES_rate_flag == 1)
	{

	}
}
void Func_Read_Adaptation(unsigned char *buffer, TS_Adaptation *packet)
{
	packet->adaptation_field_length = buffer[0];
	if (packet->adaptation_field_length > 0)
	{
		packet->discontinuity_indicator = buffer[1] >> 7 & 0x01;
		packet->random_access_indicator = buffer[1] >> 6 & 0x01;
		packet->elementary_stream_priority_indicator = buffer[1] >> 5 & 0x01;
		packet->PCR_flag = buffer[1] >> 4 & 0x01;
		packet->OPCR_flag = buffer[1] >> 3 & 0x01;
		packet->splicing_point_flag = buffer[1] >> 2 & 0x01;
		packet->transport_private_data_flag = buffer[1] >> 1 & 0x01;
		packet->adaptation_field_extension_flag = buffer[1] & 0x01;
		if (packet->PCR_flag == 1)
		{
			//packet->program_clock_reference_base = buffer[2]<<
		}
	}
}
void Func_Read_PMT(unsigned char *buffer,TS_PMT *packet)
{
	packet->table_id = buffer[0];
	packet->section_syntax_indicator = buffer[1] >> 7 & 0x01;
	packet->zero = buffer[1] >> 6 & 0x01;
	packet->reserved_1 = buffer[1] >> 4 & 0x03;
	packet->section_length = (buffer[1] & 0x0F) << 8 | buffer[2];
	packet->program_number = buffer[3] << 8 | buffer[4];
	packet->reserved_2 = buffer[5] >> 6;
	packet->version_number = buffer[5] >> 1 & 0x1F;
	packet->current_next_indicator = (buffer[5] << 7) >> 7;
	packet->section_number = buffer[6];
	packet->last_section_number = buffer[7];
	packet->reserved_3 = buffer[8] >> 5;
	packet->PCR_PID = ((buffer[8] << 8) | buffer[9]) & 0x1FFF;

	PCRID = packet->PCR_PID;

	packet->reserved_4 = buffer[10] >> 4;
	packet->program_info_length = (buffer[10] & 0x0F) << 8 | buffer[11];
	// Get CRC_32
	int len = 0;
	len = packet->section_length + 3;
	packet->CRC_32 = (buffer[len - 4] & 0x000000FF) << 24
		| (buffer[len - 3] & 0x000000FF) << 16
		| (buffer[len - 2] & 0x000000FF) << 8
		| (buffer[len - 1] & 0x000000FF);

	int pos = 12;
	// program info descriptor
	if (packet->program_info_length != 0)
		pos += packet->program_info_length;
	// Get stream type and PID    
	for (; pos <= (packet->section_length + 2) - 4; )
	{
		TS_PMT_Stream pmt_stream;
		pmt_stream.stream_type = buffer[pos];
		packet->reserved_5 = buffer[pos + 1] >> 5;
		pmt_stream.elementary_PID = ((buffer[pos + 1] << 8) | buffer[pos + 2]) & 0x1FFF;
		packet->reserved_6 = buffer[pos + 3] >> 4;
		pmt_stream.ES_info_length = (buffer[pos + 3] & 0x0F) << 8 | buffer[pos + 4];

		pmt_stream.descriptor = 0x00;
		if (pmt_stream.ES_info_length != 0)
		{
			pmt_stream.descriptor = buffer[pos + 5];

			for (int len = 2; len <= pmt_stream.ES_info_length; len++)
			{
				pmt_stream.descriptor = pmt_stream.descriptor << 8 | buffer[pos + 4 + len];
			}
			pos += pmt_stream.ES_info_length;
		}
		pos += 5;
		packet->PMT_Stream.push_back(pmt_stream);
		TS_Stream_type.push_back(pmt_stream);
	}
}
void Func_Read_PAT(unsigned char *buffer, TS_PAT *packet)
{
	packet->table_id = buffer[0];
	packet->section_syntax_indicator = buffer[1] >> 7;
	packet->zero = buffer[1] >> 6 & 0x1;
	packet->reserved_1 = buffer[1] >> 4 & 0x3;
	packet->section_length = (buffer[1] & 0x0F) << 8 | buffer[2];
	packet->transport_stream_id = buffer[3] << 8 | buffer[4];
	packet->reserved_2 = buffer[5] >> 6;
	packet->version_number = buffer[5] >> 1 & 0x1F;
	packet->current_next_indicator = (buffer[5] << 7) >> 7;
	packet->section_number = buffer[6];
	packet->last_section_number = buffer[7];

	int len = 0;
	len = 3 + packet->section_length;
	packet->CRC_32 = (buffer[len - 4] & 0x000000FF) << 24
		| (buffer[len - 3] & 0x000000FF) << 16
		| (buffer[len - 2] & 0x000000FF) << 8
		| (buffer[len - 1] & 0x000000FF);

	int n = 0;
	for (n = 0; n < packet->section_length - 12; n += 4)
	{
		unsigned  program_num = buffer[8 + n] << 8 | buffer[9 + n];
		packet->reserved_3 = buffer[10 + n] >> 5;

		packet->network_PID = 0x00;
		if (program_num == 0x00)
		{
			packet->network_PID = (buffer[10 + n] & 0x1F) << 8 | buffer[11 + n];

			TS_network_Pid = packet->network_PID; //记录该TS流的网络PID

			printf(" packet->network_PID %d \n", packet->network_PID);
		}
		else
		{
			TS_PAT_Program PAT_program;
			PAT_program.program_map_PID = (buffer[10 + n] & 0x1F) << 8 | buffer[11 + n];
			PAT_program.program_number = program_num;
			packet->program.push_back(PAT_program);

			TS_program.push_back(PAT_program);//向全局PAT节目数组中添加PAT节目信息     
		}
	}
}
void Func_Read_header(unsigned char *buf, TS_packet_header *TS_header)
{
	unsigned char buf_temp[4] = {0};
	
	memcpy(buf_temp, buf, 4);

	TS_header->sync_byte = buf_temp[0];
	TS_header->transport_error_indicator = buf_temp[1] >> 7;
	TS_header->payload_unit_start_indicator = buf_temp[1] >> 6 & 0x01;
	TS_header->transport_priority = buf_temp[1] >> 5 & 0x01;
	TS_header->PID = (buf_temp[1] & 0x1F) << 8 | buf_temp[2];
	TS_header->transport_scrambling_control = buf_temp[3] >> 6;
	TS_header->adaption_field_control = buf_temp[3] >> 4 & 0x03;
	TS_header->continuity_counter = buf_temp[3] & 0x0F; // 四位数据,应为0x0F xyy 09.03.18
}
void Func_Read(FILE *pfile,unsigned long long &ullPostion,unsigned char *buf)
{
	_fseeki64(pfile, ullPostion, SEEK_SET);

	int ir = fread_s(buf, 188, 1, 188, pfile);
	if (ir != 188)
	{
		printf("fread faile\n");
	}
	ullPostion += 188;
}
void Func_PES_Printf(TS_PES &packet)
{
	printf("**********TS_PES*************\n");
	printf("packet_start_code_prefix = %d\n", packet.packet_start_code_prefix);
	printf("stream_id = %d\n", packet.stream_id);
	printf("PES_packet_length = %d\n", packet.PES_packet_length);
	printf("PES_scrambling_control = %d\n", packet.PES_scrambling_control);
	printf("PES_priority = %d\n", packet.PES_priority);
	printf("data_alignment_indicator = %d\n", packet.data_alignment_indicator);
	printf("copyright = %d\n", packet.copyright);
	printf("original_or_copy = %d\n", packet.original_or_copy);
	printf("PES_header_data_length = %d\n", packet.PES_header_data_length);
	printf("PTS = %lld\n",packet.PTS);
	printf("DTS = %lld\n",packet.DTS);
	printf("****************************\n");
}
void Func_Adaptation_Printf(TS_Adaptation &packet)
{
	printf("************PMT**************\n");
	printf("adaptation_field_length = %d\n",packet.adaptation_field_length);
	printf("discontinuity_indicator = %d\n",packet.discontinuity_indicator);
	printf("random_access_indicator = %d\n",packet.random_access_indicator);
	printf("elementary_stream_priority_indicator = %d\n",packet.elementary_stream_priority_indicator);
	printf("PCR_flag = %d\n",packet.PCR_flag);
	printf("OPCR_flag = %d\n",packet.OPCR_flag);
	printf("splicing_point_flag = %d\n",packet.splicing_point_flag);
	printf("transport_private_data_flag = %d\n",packet.transport_private_data_flag);
	printf("adaptation_field_extension_flag = %d\n",packet.adaptation_field_extension_flag);

}
void Func_PMT_Printf(TS_PMT &ts)
{
	printf("************PMT**************\n");
	printf("table_id = %d\n",ts.table_id);
	printf("section_syntax_indicator = %d\n",ts.section_syntax_indicator);
	printf("section_length = %d\n",ts.section_length);
	printf("program_number = %d\n",ts.program_number);
	printf("version_number = %d\n",ts.version_number);
	printf("current_next_indicator = %d\n",ts.current_next_indicator);
	printf("section_number = %d\n",ts.section_number);
	printf("last_section_number = %d\n",ts.last_section_number);
	printf("PCR_PID = %d\n",ts.PCR_PID);
	printf("program_info_length = %d\n",ts.program_info_length);
	for (auto i : TS_Stream_type)
	{
		printf("stream_type = %d\n",i.stream_type);
		printf("elementary_PID = %d\n",i.elementary_PID);

	}
	printf("*****************************\n");
}
void Func_PAT_Printf(TS_PAT &ts)
{
	printf("*********PAT**************\n");
	printf("table_id=%d.\n",ts.table_id);
	printf("section_syntax_indicator=%d\n",ts.section_syntax_indicator);
	printf("section_length = %d\n",ts.section_length);
	printf("transport_stream_id = %d\n",ts.transport_stream_id);
	printf("version_number = %d\n",ts.version_number);
	printf("current_next_indicator =%d\n",ts.current_next_indicator);
	printf("section_number = %d\n",ts.section_number);
	printf("last_section_number =%d\n",ts.last_section_number);
	for (auto i : TS_program)
	{
		printf("program_number = %d\n",i.program_number);
		printf("program_map_PID = %d\n",i.program_map_PID);
	}
	printf("network_PID = %d\n",ts.network_PID);
	printf("CRC_32 = %d\n",ts.CRC_32);
	printf("************************\n");
}
void Func_Header_Printf(TS_packet_header &header)
{
	printf("******Packet Header*********\n");
	printf("sync_byte = %d.\n",header.sync_byte);
	printf("transport_error_indicator = %d.\n",header.transport_error_indicator);
	printf("payload_unit_start_indicator = %d.\n",header.payload_unit_start_indicator);
	printf("transport_priority = %d.\n",header.transport_priority);
	printf("PID  = %d.\n",header.PID);
	printf("transport_scrambling_control = %d\n",header.transport_scrambling_control);
	printf("adaptation_field_control = %d\n",header.adaption_field_control);
	printf("continuity_counter = %d\n",header.continuity_counter);
	printf("****************************\n");
}
int main(int argc, char *argv[])
{
	FILE *pfile = nullptr;
	
	errno_t er  = fopen_s(&pfile, "D:\\quanwei\\Test.ts", "rb+");
	if (er != 0)
	{
		printf("fopen_s faile\n");
	}
	
	_fseeki64(pfile, 0, SEEK_END);
	
	unsigned long long ullLen = _ftelli64(pfile);
	unsigned long long ullPostion = 0;
	unsigned char buf[188] = {0};

	TS_packet_header ts_header;
	TS_PAT			 ts_pat;
	TS_PMT			 ts_pmt;
	TS_PES			 ts_pes;

	memset(&ts_pes, 0, sizeof(TS_PES));
	memset(&ts_pat, 0, sizeof(TS_PAT));
	memset(&ts_header, 0, sizeof(TS_packet_header));

	while (ullPostion < ullLen)
	{
		Func_Read(pfile, ullPostion, buf);
			
		Func_Read_header(buf, &ts_header);
		Func_Header_Printf(ts_header);

		if (ts_header.PID == 0)//PAT
		{
			if (ts_header.payload_unit_start_indicator == 1)
			{
				Func_Read_PAT(buf+5, &ts_pat);
			}
			else
			{
				Func_Read_PAT(buf + 4, &ts_pat);
			}
			Func_PAT_Printf(ts_pat);
		}
		for (auto i: TS_program)
		{
			if (i.program_map_PID == ts_header.PID)
			{
				//PMT
				if (ts_header.payload_unit_start_indicator == 1)
				{
					Func_Read_PMT(buf + 5, &ts_pmt);
				}
				else
				{
					Func_Read_PMT(buf + 4, &ts_pmt);
				}
				Func_PMT_Printf(ts_pmt);
			}
		}
		for (auto i : TS_Stream_type)//PES
		{
			if (i.elementary_PID == ts_header.PID)
			{
				TS_Adaptation ts_adaptation;
				if (ts_header.adaption_field_control == 3)//11 第一帧PES
				{
					Func_Read_Adaptation(buf + 4, &ts_adaptation);
					Func_Adaptation_Printf(ts_adaptation);

					if (ts_adaptation.adaptation_field_length != 0)
					{
						Func_Read_PES(buf + 4 + ts_adaptation.adaptation_field_length + 1,&ts_pes);
						Func_PES_Printf(ts_pes);
					}
				}
				else//不包含PES头，只包含ES数据
				{

				}
			}
		}
	}

	fclose(pfile);

	return 0;
}