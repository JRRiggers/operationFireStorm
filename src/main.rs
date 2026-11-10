use std::collections::{HashMap};
use std::fs::{OpenOptions};
use std::io::{ Read, Write};
use std::sync::{Arc};
use std::{thread};
use std::net::{TcpListener, TcpStream};
use std::env;


#[repr(C, packed)]
struct Ctfs 
{
    keyword:u32,
    sequence: u16,
    length: u16,
    file_id:u8,
    check_sum:u32,
    padding:[u8;3],
    data:[u8; 600]
}
const CTFS_HEADER:usize=16;
const CTFS_PACKET_COUNT:usize=30;

#[repr(C, packed)]
struct EtherHeader
{
    dest:[u8;6],
    source:[u8;6],
    ether_type:u16
}
const ETHER_HEADER:usize=14;
#[repr(C, packed)]
struct IpHeader//x0800
{
    vers_len:u8,//4 is version, 4 is header length
    header_a:u8,
    length:u16,//data length
    header_b:u32,
    ttl:u8,
    protocol:u8,//6 tcp or 17 udp
    chksm:u16,
    sourceadd:u32,
    destadd:u32
}
#[repr(C, packed)]
struct Packet//6
{
    ether:EtherHeader,
    ip:IpHeader,
    data:[u8;300]
}



fn main() 
{
    let listener = TcpListener::bind("localhost:5733").unwrap();//set 
    let args: Vec<String> = env::args().collect();
    let stage=&args[1];
    for stream in listener.incoming() 
    {
        let stream = stream.unwrap();

        println!("Connection established!");
        println!("{}",stage);
        handle_connection(stream,stage);
    }
}


fn handle_connection(mut stream: TcpStream,stage:&String) 
{
    let mut buffer = [0u8; 2048];

    let mut packets: Vec<Vec<u8>>  = Vec::new();

    loop {
        
        let bytes_read = stream.read(&mut buffer).unwrap();
        //if ctfs keep, else forward to port 5744
        let data = &buffer[..bytes_read];//each set of data is a packet, i hope
        packets.push(data.to_vec());//store packets to allow them to be done in parrellel

        if bytes_read == 0 {
            println!("Connection closed");
            break;
        }
    }

    let mut i=0;
    let mut single_packet_threads=Vec::new();
    let mut double_packet_threads=Vec::new();
    let size=packets.len();
    let pokot=Arc::new(packets);
    for current in 0..size-1 {
        
        let singlebuffer=Arc::clone(&pokot);
        let doublebuffer=Arc::clone(&pokot);
        let prevbuffer=Arc::clone(&pokot);
        //calls contains keyword, with order number(i) //returns unused (front half of arrays which have been sliced or no keyword found, along with order number)

        //also handles edge case where ctfs is split between 2 arrays (requires stiching backend of array?)
        //if last packet < buffer size skip(only applicable for first few)

        let single_thread=thread::spawn(move|| singular_buffer(&singlebuffer[i],i));
        single_packet_threads.push(single_thread);
        if current!=0&&prevbuffer[i-1].len()==2048//if prev.len>2048
        {
            //dupe current by taking first 3 bytes
            let double_thread=thread::spawn(move ||double_buffer(&prevbuffer[i-1],&doublebuffer[i],i));
            double_packet_threads.push(double_thread);
        }

        //print!("{i}");
        i+=1;
    }
    println!("threads spawned");
    let packet_sets:Vec<(Vec<[usize;2]>,Vec<Vec<u8>>,usize)>=single_packet_threads.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    println!("single closed");
    let double_packet_sets:Vec<(Vec<[usize;2]>,Vec<Vec<u8>>,usize)>=double_packet_threads.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    println!("double closed");
    //need to unzip both sets into (ctfs_segments) (segments,usize)//need to take special care double packet set
    //loop 0..size
    //packet_set[i], double_set -> check if index == i
    //also sort ctfs chunks 
    let mut ctfs_vec: Vec<&Ctfs>=Vec::with_capacity(20);
    let mut ctfs_hash: HashMap<u8, Vec<&Ctfs>> = HashMap::new();
    let base_value=Ctfs{ keyword: (0), sequence: (20), length: (20),data: ([0u8;600]), file_id: (0), check_sum: (0), padding: ([0u8;3]) };
    ctfs_vec.resize(CTFS_PACKET_COUNT, &base_value);
    let endbuffer=Arc::clone(&pokot);
    let mut packet_routing: Vec<Vec<u8>>=Vec::new();
    let mut double_index=0;
    let mut segment_start=0;
    let mut ctfs_count=0;
    let mut stream44 = TcpStream::connect("127.0.0.1:5744").unwrap();
    let mut overflow=false;
    let mut index=0;
    println!("{}",packet_sets.len());


    for j in 0..packet_sets.len()
    {
        let (segment,ctfs_segment,_)=&packet_sets[j];
        if double_index<double_packet_sets.len()
        {
            let (double_seg,double_ctfs,d_index)=&double_packet_sets[double_index];
            if d_index==&j
            {
                double_index+=1;
                if double_seg.len()==0//    double empty
                {
                    let mut start=1400;
                    //throw data in, skip
                    if segment_start!=0
                    {
                        start=segment_start;
                        segment_start=0;
                        overflow=true;
                    }
                    let item=&endbuffer[j-1][start..endbuffer[j-1].len()];
                    if stage=="2"{
                        index=packet_route_add(&mut packet_routing, item, overflow, index);
                        overflow=false;
                    }
                    else {
                        stream44.write(item);
                    }
                }
                else    //double contains ctfs
                {
                    for k in 0..double_seg.len() //part[0]=1400
                    {//if segmentstart>0 ->part[0]=segmentstart
                        let mut part=double_seg[k];//72,48
                        if segment_start!=0
                        {
                            part[0]=segment_start;
                            segment_start=0;
                            overflow=true;
                        }
                        if part[1]>2048
                        {
                            segment_start=part[1]-2048;
                            part[1]=2048;
                            continue;
                        }
                        let item=&endbuffer[j-1][part[0]..part[1]];//cap end at end of buffer then overflow(segmentstart)
                        //send item
                        if stage=="2"{
                            index=packet_route_add(&mut packet_routing, item, overflow, index);
                            overflow=false;
                        }
                        else {
                            stream44.write(item);
                        }
                    }
                    for i in 0..double_ctfs.len()
                    {
                        //convert to stuct
                        ctfs_count+=1;
                        let mut temp:Option<&mut Ctfs>=None;
                        unsafe 
                        {
                            temp =found_pattern(&double_ctfs[i]);
                        }
                        //add to ctfs vec at seqence pos
                        match temp.unwrap() {
                            observed => {
                                let sequence=observed.sequence;
                                let file=observed.file_id;
                                //println!("{}",sequence.swap_bytes());
                                //read 0..len on data
                                if stage=="1"
                                {
                                    ctfs_vec[sequence.swap_bytes() as usize]=observed;
                                }
                                else {
                                    //sort by file id
                                    //ctfs_hash.insert(file, observed);
                                    let file_vec:Option<&mut Vec<&Ctfs>>  =ctfs_hash.get_mut(&file);
                                    match file_vec {
                                        Some(found)=>{
                                            found.push(observed);
                                        }
                                        None=>{
                                            let mut found: Vec<&Ctfs> =Vec::new();
                                            found.push(observed);
                                            ctfs_hash.insert(file, found);
                                        }
                                    }
                                    //ctfs_hash[&file].push(observed);
                                }
                            }
                            _ => (),
                        }
                        
                    }
                }
            }   //end double check
        }

        if segment.len()==0//           single no ctfs
        {//unless double
            let mut start=0;
            let mut end=endbuffer[j].len();
            if segment_start!=0
            {
                start=segment_start;
                segment_start=0;
                overflow=true;
            }
            if end==2048
            {
                end=1400;
            }
            let item=&endbuffer[j][start..end];
            if stage=="2"{
                index=packet_route_add(&mut packet_routing, item, overflow, index);
                overflow=false;
            }
            else {
                stream44.write(item);
            }
            
        }
        else {                      //single contains ctfs
            for k in 0..segment.len() //part[0]=1400
            {//if segmentstart>0 ->part[0]=segmentstart
                let mut part=segment[k];
                if segment_start!=0
                {
                    part[0]=segment_start;
                    segment_start=0;
                    overflow=true;
                }
                let item=&endbuffer[j][part[0]..part[1]];
                if stage=="2"{
                    index=packet_route_add(&mut packet_routing, item, overflow, index);
                    overflow=false;
                }
                else {
                    stream44.write(item);
                }
                
                //send item
                if part[1]>=1400&&endbuffer[j].len()==2048//>=end, if this.len>2048
                {
                    println!("start replaced:{}",part[1]);
                    segment_start=part[1];
                    overflow=true;
                }
            }
            for i in 0..ctfs_segment.len()
            {
                //convert to stuct
                //let part=Arc::new(ctfs_part);
                ctfs_count+=1;
                let mut temp:Option<&mut Ctfs>=None;
                unsafe 
                {
                    temp =found_pattern(&ctfs_segment[i]);
                }
                //add to ctfs vec at seqence pos
                match temp.unwrap() {
                    observed => {
                        let sequence=observed.sequence;
                        let file=observed.file_id;
                        //read 0..len on data
                        if stage=="1"
                        {
                            ctfs_vec[sequence.swap_bytes() as usize]=observed;
                        }
                        else {
                            //sort by file id
                            //ctfs_hash.insert(file, observed);
                            let file_vec:Option<&mut Vec<&Ctfs>>  =ctfs_hash.get_mut(&file);
                            match file_vec {
                                Some(found)=>{
                                    found.push(observed);
                                }
                                None=>{
                                    let mut found: Vec<&Ctfs> =Vec::new();
                                    found.push(observed);
                                    ctfs_hash.insert(file, found);
                                }
                            }
                            //ctfs_hash[&file].push(observed);
                        }
                    }
                    _ => (),
                }

            }
        }
    }
    println!("end");
    println!("{}",ctfs_count);
    //stream.shutdown(Shutdown::Write).unwrap();
    //collect results order ctfs segments by order number

    //
    if stage=="1"
    {
        compile_file(ctfs_vec);
    }
    else {
        compile_file_stage2(ctfs_hash);
        let mut stream45 = TcpStream::connect("127.0.0.1:5745").unwrap();
        let mut stream46 = TcpStream::connect("127.0.0.1:5746").unwrap();
        let mut p44:Vec<Vec<u8>>=Vec::new();
        let mut p45:Vec<Vec<u8>>=Vec::new();
        let mut p46:Vec<Vec<u8>>=Vec::new();
        for i in 0..packet_routing.len() {
            let (mut packet44,mut packet45,mut packet46)=extract_ether_packets(&packet_routing[i]);
            p44.append(&mut packet44);
            p45.append(&mut packet45);
            p46.append(&mut packet46);
        }

        send_packet_vector(p44, stream44);
        println!("port44 done");
        send_packet_vector(p45, stream45);//send to 44 as well
        println!("port45 done");
        send_packet_vector(p46, stream46);
        println!("port46 done");
    }




}


fn double_buffer(buffer: &Vec<u8>,next: &Vec<u8>,index: usize)->(Vec<[usize;2]>,Vec<Vec<u8>>,usize)  //handles 2 next to eachother, could have this handle the latter half as this already has both packets instead of needing to send a request
{                                                                   //return start points for segments
    //scan last 4bytes for C
    //scan last 600 bytes

    let keyword="CTFS".as_bytes();
    let mut segments:Vec<[usize;2]>=Vec::new();//stores pos of start to end
    let mut ctfs_segments:Vec<Vec<u8>>=Vec::new();//would be ctfs type, would need to return incomplete sections
    // Simple check using windows()
    let start =1400;
    let mut i=start;//start
    let mut last_occurance=i;//=start
    let size=buffer.len()-3;
    loop {
        if buffer[i] ==keyword[0]&&i<size
        {
            if buffer[i+1]==keyword[1]{if buffer[i+2]==keyword[2]{if buffer[i+3]==keyword[3] {
                //match, 
                //extract
                segments.push([last_occurance,i]);//store last_occurance and i, 
                let mut length=0;
                if buffer.len()-i<8//requires next segment to obtain length
                {
                    println!("bytes left: {}",buffer.len()-i);
                    let bytes_left=buffer.len()-i;
                    if bytes_left<7
                    {
                        length=u16::from_be_bytes([next[6-bytes_left],next[7-bytes_left]]).into();
                    }
                    else {
                        length=u16::from_be_bytes([buffer[2047],next[0]]).into();
                    }
                }
                else {
                    length=u16::from_be_bytes([buffer[i+6],buffer[i+7]]).into();
                }
                if buffer.len()-i<length+CTFS_HEADER//data split between buffers
                {
                    let bytes_left=buffer.len()-i;
                    //break/ store overflow request for next segement
                    ctfs_segments.push([&buffer[i..i+bytes_left],&next[0..length+CTFS_HEADER-bytes_left]].concat().to_vec());
                }
                else {
                    ctfs_segments.push(buffer[i..i+length+CTFS_HEADER].to_vec());
                }
                i+=length+CTFS_HEADER;
                last_occurance=i;

                i-=1;//if theres a double packet
                //skip by total length
            }}}
        }
        i+=1;
        if i>=size//goes into next buffer, ie check the first 3 bytes for TFS FS S
        {
            if i>=size+3//goes into next buffer, ie check the first 3 bytes for 
            {
                break;
            }                                   //TFS FS S
            let bytes_left:i16=(buffer.len()-i-1) as i16;//1  2  3
            //println!("{},67",buffer[i]);
            if buffer[i] ==keyword[0]
            {
                for j in 0..3
                {
                    if i+j+1>=2048//into next buffer
                    {
                        if next[((bytes_left-j as i16)).unsigned_abs() as usize] ==keyword[(1+j) as usize]
                        {
                            if j==2
                            {
                                segments.push([last_occurance,i]);
                                //found match
                                let bytes_left:usize=bytes_left as usize+1;
                                let length:usize=u16::from_be_bytes([next[6-bytes_left],next[7-bytes_left]]).into();
                                ctfs_segments.push([&buffer[i..i+bytes_left],&next[0..length+CTFS_HEADER-bytes_left]].concat().to_vec());
                                i+=length+CTFS_HEADER;
                                last_occurance=i;
                                segments.push([last_occurance,last_occurance]);
                                return (segments,ctfs_segments,index);
                            }
                        }
                        else {
                            break;
                        }
                    }
                    else {
                        let pos=j as usize;
                        println!("pos:{}, item: {}",pos,buffer[i+pos+1]);
                        if buffer[i+pos+1] !=keyword[(1+j)as usize] {
                            break;
                        }
                    }
                }
            }
        }
    }
    if last_occurance!=start&&last_occurance!=i
    {
        segments.push([last_occurance,2048]);//if last_oc==start
    }           //if last==end ignore 
    if last_occurance==i
    {
        segments.push([last_occurance,last_occurance]);
    }

    return (segments,ctfs_segments,index);
}

//take and return buffer index

unsafe fn found_pattern(buf_slice:&[u8])->Option<&mut Ctfs>//slices at start (includes ctfs) and rest of the 
{
    //throw into struct
    return Some(&mut *(buf_slice.as_ptr() as *mut Ctfs));//returns this, all values are in the incorrect endian
}

unsafe fn convert_eth_ip(buf_slice:&[u8])->Option<&mut Packet>//slices at start (includes ctfs) and rest of the 
{
    return Some(&mut *(buf_slice.as_ptr() as *mut Packet));//returns this, all values are in the incorrect endian
}

fn compile_file(ctfs_segments: Vec<&Ctfs>)
{
    //create file, throw data into it
    let mut file = OpenOptions::new()
        .create(true)      
        .append(true)     
        .open("ctfs.pdf").unwrap();

    for i in 0..ctfs_segments.len()
    {
        if ctfs_segments[i].keyword==0//checks end of data due to filling with default values
        {
            break;
        }
        file.write(&ctfs_segments[i].data[0..ctfs_segments[i].length.swap_bytes() as usize]).unwrap();
    }
    println!("File created");
    //foreach append data to file
    //write all data into file


}

fn compile_file_stage2(ctfs_segments: HashMap<u8, Vec<&Ctfs>>)
{
    for (i,mut vector )in ctfs_segments
    {
        let string_i = i.to_string();
        let str_i=string_i.as_str();
        let file_name=format!("{str_i}.pdf");
        let mut file = OpenOptions::new()
        .create(true)      
        .append(true)     
        .open(file_name).unwrap();
        vector.sort_by(|a,b|a.sequence.swap_bytes().cmp(&b.sequence.swap_bytes()));
        for j in 0..vector.len(){
            file.write(&vector[j].data[0..vector[j].length.swap_bytes() as usize]).unwrap();
        }
        
    }
}

fn singular_buffer(buffer: &Vec<u8>,index: usize)->(Vec<[usize;2]>,Vec<Vec<u8>>,usize)  {

    let keyword="CTFS".as_bytes();
    let mut segments:Vec<[usize;2]>=Vec::new();//contains non ctfs data
    let mut ctfs_segments:Vec<Vec<u8>>=Vec::new();//would be ctfs type, would need to return incomplete sections
    
    let mut i=0;//start
    let mut last_occurance=i;//=start
    
    if buffer.len()<4
    {
        return (segments,ctfs_segments,index);
    }
    let mut end=buffer.len()-3;
    let mut end_slice=end+3;
    if end==2048-3
    {
        end=1400;
        end_slice=end;
    }
    loop {
        if buffer[i] ==keyword[0]
        {

            if buffer[i+1]==keyword[1]{if buffer[i+2]==keyword[2]{if buffer[i+3]==keyword[3] {
                //match, 
                //extract
                segments.push([last_occurance,i]);
                let length:usize=u16::from_be_bytes([buffer[i+6],buffer[i+7]]).into();
                ctfs_segments.push(buffer[i..i+length+CTFS_HEADER].to_vec());
                i+=length+CTFS_HEADER;
                last_occurance=i;
                i-=1;//if theres a double packet

                //skip by total length
            }}}
        }
        i+=1;
        if i>=end
        {
            if last_occurance!=0 &&last_occurance!=i
            {
                
                segments.push([last_occurance,end_slice]);
            }
            if last_occurance==i
            {
                segments.push([last_occurance,last_occurance]);
            }
            return (segments,ctfs_segments,index);
        }
    }
}

fn extract_ether_packets(buffer: &Vec<u8>)->(Vec<Vec<u8>>,Vec<Vec<u8>>,Vec<Vec<u8>>)//all ctfs packets have been filtered out
{
    let end=buffer.len();
    //let mut void_packets=Vec::new();
    let mut p5745_packets: Vec<Vec<u8>>=Vec::new();
    let mut p5744_packets: Vec<Vec<u8>>=Vec::new();
    let mut p5746_packets: Vec<Vec<u8>>=Vec::new();
    let mut i=0;
    loop {
        let length:usize=u16::from_be_bytes([buffer[i+16],buffer[i+17]]).into();
        println!("length: {}",length);
        let packet_vec=buffer[i..i+length+ETHER_HEADER].to_vec();
        i+=length+ETHER_HEADER-1;
        unsafe 
        {
            let packet =convert_eth_ip(&packet_vec).unwrap();//if ether add is in a set, send whole packet elsewhere
            let source=packet.ether.source;
            let dest=packet.ether.dest;
            let pack_source: u32=u32::from_be_bytes([0,source[0],source[1],source[2]]);
            let pack_dest: u32=u32::from_be_bytes([0,dest[0],dest[1],dest[2]]);
            
            match pack_source {
                0x000c29|0x005056|0x001c14 =>   {
                    //drop
                }
                _ =>    {
                    match  pack_dest{
                        0x001aa0|0x001ec9|0x00155d =>   {
                            p5745_packets.push(packet_vec.to_vec());
                        }
                        _=> {}
                    }
                    if packet.ip.protocol==6
                    {
                        p5744_packets.push(packet_vec);
                    }
                    else {
                        p5746_packets.push(packet_vec);
                    }
                }
            }
        }

        i+=1;
        if i>=end
        {
            break;
        }
    }
    return (p5744_packets,p5745_packets,p5746_packets);
}

//merges non ctfs packets together
fn packet_route_add(out_vec:&mut Vec<Vec<u8>>,buf_slice:&[u8],overflow:bool,mut index:usize)->usize//overflow on reaching end, not on start offset
{
    if buf_slice.len()==0
    {
        return index;
    }
    if out_vec.len()==0
    {
        out_vec.push(buf_slice.to_vec());
    }
    let current=&mut out_vec[index];//is len==0 push
    if current.len()<=600 ||overflow
    {
        current.append(&mut buf_slice.to_vec());
    }
    else {
        index+=1;
        out_vec.push(buf_slice.to_vec());
    }
    
    return index;
    //index+=overflow.into();
}

fn send_packet_vector(packets:Vec<Vec<u8>>,mut stream: TcpStream)
{
    if packets.len()==0
    {
        return;
    }
    for item in packets {
        stream.write(&item);
    }
}