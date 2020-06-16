module Lib
  ( processPacket,
  )
where

import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BSC8
import Network.Pcap

interfaceName :: String
interfaceName = "lo0"

filterString :: String
filterString = "dst host 127.0.0.1 and port 8888"

packetCount :: Int
packetCount = 1

printPacketAsHex :: CallbackBS
printPacketAsHex _ bs = do
  BSC8.putStrLn (B16.encode bs)

processPacket :: IO ()
processPacket = do
  -- TODO: lookupNet only supports IPv4; support IPv6
  lo0network <- lookupNet interfaceName
  let lo0netMask = netMask lo0network
  -- TODO: Name magic constants
  pcapHandle <- openLive interfaceName 100 True 5000
  setFilter pcapHandle filterString True lo0netMask
  loopBS pcapHandle packetCount printPacketAsHex
  return ()
