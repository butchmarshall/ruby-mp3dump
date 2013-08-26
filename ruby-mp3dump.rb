#!/usr/local/bin/ruby
require 'tempfile'
require 'rubygems' 
require 'pcaplet'
require 'id3lib'
require 'tmpdir'
include Pcap

class TcpStream
  attr_accessor :ip_dst, :ip_src, 
                :tcp_dport, :tcp_sport,
                :packets, :capture,
		:out_dir
                
  def initialize(ip_dst, ip_src, tcp_dport, tcp_sport, capture, out_dir)
    @packets = []
    @ip_dst = ip_dst
    @ip_src = ip_src
    @tcp_dport = tcp_dport
    @tcp_sport = tcp_sport
    @capture = capture
    @out_dir = out_dir
  end

  def add_packet(p)
    self.packets << p if p.methods.include?("tcp_data") && !p.tcp_data.nil?
  end

  def write_stream
    f = Tempfile.new('stream', Dir.tmpdir)
    file_path = f.path
    f.close(true)

    f = File.open(file_path, File::WRONLY|File::TRUNC|File::CREAT, 0755)
    f.flock(File::LOCK_EX)
    self.packets.sort { |a,b| a.tcp_seq <=> b.tcp_seq }.each { |p|
        if p.methods.include?("tcp_data")
          f.print( p.tcp_data ) 
        end
    }
    f.flock(File::LOCK_UN)
    f.close()

    tag = ID3Lib::Tag.new(file_path)

    mp3_path = "#{file_path}.mp3"
    system("ffmpeg -i #{file_path} -ab 160k #{mp3_path}")

    FileUtils.rm("#{file_path}")

    if !File.directory?(self.out_dir)
	FileUtils.mkdir_p(self.out_dir)
    end

    if !tag.artist.to_s.empty? && !tag.title.to_s.empty?
      name = File.basename("#{tag.artist} - #{tag.title}.mp3")
    else
      name = File.basename(mp3_path)
    end

    FileUtils.mv(mp3_path, "#{self.out_dir}/#{name}")
    puts "Saved MP3: #{name}"

  end

end

class StreamDump
  attr_accessor :streams, :capture, :out_dir

  def initialize(capture, out_dir)
    @streams = []
    @capture = capture
    @out_dir = out_dir
  end

  def filter_packet(p)
    stream = nil

    # Find existing stream
    self.streams.each { |s|
      if (s.ip_dst == p.ip_dst) && (s.ip_src == p.ip_src) && (s.tcp_dport == p.tcp_dport) && (s.tcp_sport == p.tcp_sport)
        stream = s
        break
      end
    }
  
    if stream.nil?
      stream = TcpStream.new(p.ip_dst, p.ip_src, p.tcp_dport, p.tcp_sport, self.capture, self.out_dir)
      self.streams << stream
    end

    stream.add_packet(p)

    if p.tcp_fin?

      if stream.packets.length > 0 && stream.packets.first.tcp_data =~ /audio\/mpeg/         
        puts "Finished reading audio/mpeg tcp stream"

        puts "Tracking #{self.streams.length} streams.."

        stream.write_stream
      end

      self.streams.delete(stream)
    end

  end

end

if ARGV.length != 2
	puts "Please specify both interface and directory"
end

interface = ARGV.shift()
dir = ARGV.shift()


capture = Capture.open_live(interface, 1600)

s = StreamDump.new(capture, dir)


capture.each_packet { |p|
  s.filter_packet(p) if p.tcp?
}





















