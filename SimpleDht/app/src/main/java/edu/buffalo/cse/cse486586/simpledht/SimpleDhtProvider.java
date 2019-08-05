package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

import static android.content.ContentValues.TAG;


public class SimpleDhtProvider extends ContentProvider {

    String myPort;
    static final int SERVER_PORT = 10000;
    private String masterid = "11108";
    private ArrayList<String> portlist = new ArrayList<String>();
    private HashMap<String,String> DB = new HashMap<String, String>();
    MatrixCursor cursor = null;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        if(selection.equals("@")){
            DB.clear();
        }
        else if(selection.equals("*")){
            for(int i = 0 ; i < portlist.size() ; i++){
                String del_all = "DeleteStar" + ":" + "not" + ":" + portlist.get(i);
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , del_all);
            }
        }
        else{
            String dport = destinationPort(selection);
            String del_key = "Delete" + ":" + "not" + ":" + dport + ":" + selection;
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, del_key);
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub

        String key = values.get("key").toString();
        String value = values.get("value").toString();
        Log.i(TAG,"key to insert" + "--" + key);
        Log.i(TAG,"value to insert" + "--" + value);
        if(only_node()){
            Log.e(TAG, "inserting only node");
            DB.put(key,value);
            return uri;
        }
        String destport = destinationPort(key);
        Log.e(TAG,"Destination Port" + "--" + destport);
        String message = "UpdateKey" + ":" + "not" + ":" + destport + ":" + key + ":" + value;
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , message );

        return null;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub

        //Log.e(TAG, "My port = " + myPort);
        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);

        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }
        portlist.add(getPort());
        String message = "";
        String port = getPort();
        if(port.equals(masterid)){
            Log.e(TAG,"Valid master cond");
           // portlist.add(port);
            for(int i = 0 ; i < portlist.size() ; i++){
                Log.e(TAG,"Portlist data" + "--" + portlist.get(i));
            }
        }
        else{
            //portlist.add(getPort());
            message = "NewNode" + ":" + port + ":" + masterid;
            Log.e(TAG,"Message to send from slse par" + "--" + message);
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , message );
        }


        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO Auto-generated method stub
        Log.e(TAG,"Query type" + "--" + selection);
        cursor = new MatrixCursor(new String[] {"key","value"});

        String portCur = getPort();
        if(selection.equals("@")){
            Log.e(TAG, "inside if @ size = " + DB.size());
            for (Map.Entry<String,String> entry : DB.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                cursor.addRow(new String[]{key, value});
            }
        }
        else if(selection.equals("*")) {


            for (Map.Entry<String, String> entry : DB.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                cursor.addRow(new String[]{key, value});
            }

            if (!only_node()) {
                for (String remotePort : portlist) {
                    if (remotePort.equals(portCur)) continue;
                    String message_star = "QueryStar" + ":" + portCur + ":" + remotePort;
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , message_star);
                    synchronized (cursor){
                        try{
                            cursor.wait();
                        }catch (Exception e){
                            Log.e(TAG, "Lock Exception ");
                            e.printStackTrace();
                        }
                    }
                }
            }


        }
        else{
            if(only_node()){
                Log.e(TAG, "get only node");
                String key = selection;
                String value = DB.get(selection);
                Log.e(TAG, "query key value only node = " + key + " " + value);
                cursor.addRow(new String[]{key, value});
                return cursor;
            }
            String dport = destinationPort(selection);
            String message = "QueryRequest" + ":" + portCur + ":" + dport + ":" + selection;
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , message);
            synchronized (cursor){
                try{
                    cursor.wait();
                }catch (Exception e){
                    Log.e(TAG, "Lock Exception ");
                    e.printStackTrace();
                }
            }

        }

        return cursor;

    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private String getHash(String value){

        String hash_val = "";
        try{
            hash_val = genHash(value);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return hash_val;
    }

    private String getPort(){
        TelephonyManager tel = (TelephonyManager)this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        Log.e(TAG, "Get Own Port = " + myPort);
        return myPort;
    }

    private String destinationPort(String Keys){

        ArrayList<String> temp1 = new ArrayList<String>();
        temp1.addAll(portlist);

        //String hash_key = getHash(key);
        temp1.add(Keys);
        Collections.sort(temp1,new Compared());
        int index = temp1.indexOf(Keys);
        String destport;
        if(index == temp1.size() - 1)
            destport = temp1.get(0);
        else
            destport = temp1.get(index + 1);
        for(int i = 0 ; i < temp1.size() ; i++){
            Log.e(TAG,"Temp1 Data" + "--" + temp1.get(i));
        }
        return destport;

    }


    public class Compared implements Comparator<String>{

        @Override
        public int compare(String lhs, String rhs) {
            String l, r;
            try {
                l = getHash(String.valueOf(Integer.parseInt(lhs)/2));
            } catch (NumberFormatException e) {
                l = getHash(lhs);
            }
            try {
                r = getHash(String.valueOf(Integer.parseInt(rhs)/2));
            } catch (NumberFormatException e) {
                r = getHash(rhs);
            }
            return l.compareTo(r);
        }
    }

    public boolean only_node(){

            return (portlist.size() == 1);
    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            Log.e(TAG, "Socket Accepted");
            String msgClient = null;
            try {
                while (true) {
                    Log.e(TAG, "In Server");
                    Socket s = serverSocket.accept();
                    InputStream in = s.getInputStream();
                    DataInputStream data = new DataInputStream(in);
                    msgClient = data.readUTF();
                    Log.e(TAG,"Message recvd from client" + "--" + msgClient);
                    String message[] = msgClient.split(":");
                    String task = message[0];


                    if(task.equals("NewNode")){
                        Log.e(TAG, "New Node Task");
                        String curPort = message[1];
                        portlist.add(curPort);
                        for(int i = 0 ; i < portlist.size() ; i++){
                            Log.e(TAG,"Portlist data b4 sort" + "--" + portlist.get(i));
                        }
                        Collections.sort(portlist,new Compared());

                        for(int i = 0 ; i < portlist.size() ; i++){
                            Log.e(TAG,"Portlist data" + "--" + portlist.get(i));
                        }
                        node_join(portlist);

                    }
                    else if(task.equals("UpdateNode")){
                        Log.e(TAG, "Update Node ");
                        Log.e(TAG, "Update Node ka message 3 " + "--" + message[3]);
                        String  split[]  = message[3].split("#");
                        Log.e(TAG,"after split values" + "--" + split[0]);
                        Log.e(TAG,"after split values" + "--" + split[1]);

                        portlist.clear();
                        portlist.addAll(Arrays.asList(split));

                        for(int i = 0 ; i < portlist.size() ; i++){
                            Log.e(TAG," local templist data" + "--" + portlist.get(i));
                        }
                    }
                    else if(task.equals("UpdateKey")){
                        Log.e(TAG,"Update New Key");
                        Context context = getContext();
                        String key = message[3];
                        String value = message[4];
                        DB.put(key,value);
                        for (String name: DB.keySet()){

                            String k =name.toString();
                            String v = DB.get(name).toString();
                            Log.e(TAG,"DB key val pair" +"--" + k + "::" + v);


                        }

                    }

                    else if(task.equals("QueryRequest")){
                        Log.e(TAG, "QueryRequest");
                        String search = message[3];
                        String portQuery = message[1];
                        String line = DB.get(search);
                        String querysuccess = "QueryFullfilled" + ":" + "not" + ":" + portQuery + ":" + search + ":" + line;
                        query_done(querysuccess);

                    }

                    else if(task.equals("QueryFullfilled")){
                        Log.e(TAG, "QueryFullfilled");
                        String key = message[3];
                        String val = message[4];
                        synchronized (cursor) {
                            cursor.addRow(new String[]{  key,val });
                            cursor.notify();
                        }


                    }

                    else if(task.equals("QueryStar")){
                        Log.e(TAG, "QueryStar");
                        String port_seek = message[1];
                        String query_return = "StarDone" + ":" + "not" + ":" + port_seek + ":";
                        if(DB.size() != 0){
                            for (Map.Entry<String,String> entry : DB.entrySet()){

                                String key = entry.getKey();
                                String value = entry.getValue();
                                query_return += key + "#" + value + "@";
//                            query_done(query_return);
                            }
                            query_done(query_return);
                        }
                        else{
                            String no_query_return = "StarDone" + ":" + "not" + ":" + port_seek + ":" + "DBEmpty";
                            query_done(no_query_return);
                        }


                    }

                    else if(task.equals("StarDone")){
                        Log.e(TAG, "StarDone");
                        String key_val = message[3];
                        Log.e(TAG,"keyval ka msgg" + "--" + key_val);
                        if(key_val.equals("DBEmpty")){
                            synchronized (cursor){
                                cursor.notify();
                            }
                        }
                        else{
                            String keyvalPair[] = key_val.split("@");
                            Log.e(TAG,"key val pair data" + "--" + keyvalPair[0]);
                            for(int i = 0 ; i < keyvalPair.length ; i++){
                                String splitter[] = keyvalPair[i].split("#");

                                String key = splitter[0];
                                String val = splitter[1];
                                Log.e(TAG,"key and value obtained" + "--" + key + "--" + val);
                                //synchronized (cursor) {
                                cursor.addRow(new String[]{  key,val });
                                //counter ++;
                                //}
                            }
                            synchronized (cursor){
                                cursor.notify();
                            }
                        }


                    }

                    else if(task.equals("Delete")){
                        DB.remove(message[3]);
                    }

                    else if(task.equals("DeleteStar")){
                        DB.clear();
                    }

                }
            } catch (IOException e) {
                Log.e(TAG, "Server Socket IO exception ");
            }
            return null;
        }

        protected void onProgressUpdate(String...strings){
//

        }

        public void node_join ( ArrayList plist) {
            String list = "";
            for (int i = 0; i < plist.size(); i++) {
                if(i == plist.size() - 1){
                    list += plist.get(i);
                }
                else
                    list += plist.get(i) + "#";
            }
            for(int i = 0 ; i < plist.size() ; i++){
                String msgUpdate = "UpdateNode" + ":" + "not" + ":" + plist.get(i) + ":" + list;
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , msgUpdate );
            }


        }

        public void query_done(String msg){
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR , msg );
        }

    }


    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
            try {
                Log.e(TAG, "In Client");
                String msg = msgs[0];
                String message[] = msg.split(":");
                String destPort = message[2];
                Log.e(TAG, "Data send from client to dest port" + "--" + destPort);
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(destPort));
                OutputStream out = socket.getOutputStream();
                DataOutputStream d = new DataOutputStream(out);
                Log.e(TAG,"message to send from client" + "=" + msgs[0]);
                d.writeUTF(msg);
                d.flush();
            } catch (UnknownHostException e) {
                Log.e(TAG, "ClientTask UnknownHostException");
            } catch (IOException e) {
                Log.e(TAG, "ClientTask socket IOException");
            }


            return null;
        }
    }

}
