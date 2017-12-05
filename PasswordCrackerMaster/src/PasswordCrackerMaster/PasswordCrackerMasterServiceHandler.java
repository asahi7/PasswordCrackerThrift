package PasswordCrackerMaster;

import org.apache.thrift.TException;
import org.apache.thrift.async.AsyncMethodCallback;
import org.apache.thrift.async.TAsyncClientManager;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TNonblockingSocket;
import org.apache.thrift.transport.TSocket;
import thrift.gen.PasswordCrackerMasterService.PasswordCrackerMasterService;
import thrift.gen.PasswordCrackerWorkerService.PasswordCrackerWorkerService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static PasswordCrackerMaster.PasswordCrackerConts.SUB_RANGE_SIZE;
import static PasswordCrackerMaster.PasswordCrackerConts.WORKER_PORT;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.jobInfoMap;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.workersAddressList;

public class PasswordCrackerMasterServiceHandler implements PasswordCrackerMasterService.Iface {
    public static List<TSocket> workersSocketList = new LinkedList<>();  //Connected Socket
    public static List<String> workersAddressList = new LinkedList<>(); // Connected WorkerAddress
    public static ConcurrentHashMap<String, PasswordDecrypterJob> jobInfoMap = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, Long> latestHeartbeatInMillis = new ConcurrentHashMap<>(); // <workerAddress, time>
    public static ExecutorService workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
    public static ScheduledExecutorService heartBeatCheckPool = Executors.newScheduledThreadPool(1);

    public static ConcurrentHashMap<String, List<PassHolder>> workersRangeMap = new ConcurrentHashMap<>(); // !!!

    private static class PassHolder { // !!!
    	public String encPass;
    	public long rangeBegin;
    	public long subRangeSize;
    	public PassHolder(String encPass, long rangeBegin, long subRangeSize) {
    		this.encPass = encPass;
    		this.rangeBegin = rangeBegin;
    		this.subRangeSize = subRangeSize;
		}
    }
    
    /*
     * The decrypt method create the job and put the job with jobId (encrypted Password) in map.
     * And call the requestFindPassword and if it finds the password, it return the password to the client.
     */
    @Override
    public String decrypt(String encryptedPassword) throws TException {
        PasswordDecrypterJob decryptJob = new PasswordDecrypterJob();
        jobInfoMap.put(encryptedPassword, decryptJob);

        /** COMPLETE **/
        String password = null;
        requestFindPassword(encryptedPassword, 0, (PasswordCrackerConts.TOTAL_PASSWORD_RANGE_SIZE + workersAddressList.size() - 1) / workersAddressList.size()); // IMPORTANT: check if rangeBegin indeed should be zero
        							// What will happen if one worker is dead already, and we don't change the val of SUB_RANGE_SIZE?
        try {
			password = decryptJob.getPassword();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return password;
    }

    /*
     * The reportHeartBeat receives the heartBeat from workers.
     * Consider the checkHeartBeat method and use latestHeartbeatInMillis map.
    */
    @Override
    public void reportHeartBeat(String workerAddress)
            throws TException {
        /** COMPLETE **/
    	latestHeartbeatInMillis.put(workerAddress, System.currentTimeMillis());
    }

    /*
     * The requestFindPassword requests workers to find password using RPC in asynchronous way.
    */
    public static void requestFindPassword(String encryptedPassword, long rangeBegin, long subRangeSize) {
        PasswordCrackerWorkerService.AsyncClient worker = null;
        FindPasswordMethodCallback findPasswordCallBack = new FindPasswordMethodCallback(encryptedPassword);
        try {
            int workerId = 0;
            for (String workerAddress : workersAddressList) {
            	// IMPORTANT: should we also check if the worker is dead already before assigning?
                long subRangeBegin = rangeBegin + (workerId * subRangeSize);
                long subRangeEnd = subRangeBegin + subRangeSize;
                
                if(! workersRangeMap.containsKey(workerAddress)) { // !!!
                	workersRangeMap.put(workerAddress, new ArrayList<PassHolder>());
                }
                workersRangeMap.get(workerAddress).add(new PassHolder(encryptedPassword, subRangeBegin, subRangeSize)); /// !!!
                
                worker = new PasswordCrackerWorkerService.AsyncClient(new TBinaryProtocol.Factory(), new TAsyncClientManager(), new TNonblockingSocket(workerAddress, WORKER_PORT));
                worker.startFindPasswordInRange(subRangeBegin, subRangeEnd, encryptedPassword, findPasswordCallBack);
                workerId++;
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        catch (TException e) {
            e.printStackTrace();
        }
    }

    /*
     * The redistributeFailedTask distributes the dead workers's job (or a set of possible password) to active workers.
     *
     * Check the checkHeartBeat method
     */
    public static void redistributeFailedTask(ArrayList<String> failedWorkerAddressList) {
        /** COMPLETE **/
    	for(String workerAddress : failedWorkerAddressList) {
    		if(workersRangeMap.contains(workerAddress)) {
    			for(PassHolder passHolder : workersRangeMap.get(workerAddress)) {
    				requestFindPassword(passHolder.encPass, passHolder.rangeBegin, passHolder.subRangeSize / workersAddressList.size());
    			}
    			workersRangeMap.remove(workerAddress);
    		}
    	}
    }

    /*
     *  If the master didn't receive the "HeartBeat" in 5 seconds from any workers,
     *  it considers the workers that didn't send the "HeartBeat" as dead.
     *  And then, it redistributes the dead workers's job in other alive workers
     *
     *  hint : use latestHeartbeatinMillis, workerAddressList
     *
     *  you must think about when several workers is dead.
     *
     *  and use the workerPool
     */
    public static void checkHeartBeat() {
        /** COMPLETE **/
        int workerId = 0;
        final long thresholdAge = 5_000;

        ArrayList<String> failedWorkerAddressList = new ArrayList<>();

        Iterator<String> iteratorAddress = workersAddressList.iterator();
        Iterator<TSocket> iteratorSocket = workersSocketList.iterator();
        while(iteratorAddress.hasNext()) {
        	String workerAddress = iteratorAddress.next();
        	iteratorSocket.next();
        	if(System.currentTimeMillis() - latestHeartbeatInMillis.get(workerAddress) > thresholdAge) {
        		failedWorkerAddressList.add(workerAddress);
        		iteratorAddress.remove();
        		iteratorSocket.remove();
        	}
        	workerId++;
        }
        
        redistributeFailedTask(failedWorkerAddressList);
    }
}

//CallBack
class FindPasswordMethodCallback implements AsyncMethodCallback<PasswordCrackerWorkerService.AsyncClient.startFindPasswordInRange_call> {
    private String jobId;

    FindPasswordMethodCallback(String jobId) {
        this.jobId = jobId;
    }
    /*
     *  if the returned result from worker is not null, it completes the job.
     *  and call the jobTermination method
     */
    @Override
    public void onComplete(PasswordCrackerWorkerService.AsyncClient.startFindPasswordInRange_call startFindPasswordInRange_call) {
        try {
            String findPasswordResult = startFindPasswordInRange_call.getResult();
            /** COMPLETE **/
            if(findPasswordResult != null) {
            	jobInfoMap.get(jobId).setPassword(findPasswordResult);
            	jobTermination(jobId);
            }
        }
        catch (TException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onError(Exception e) {
        System.out.println("Error : startFindPasswordInRange of FindPasswordMethodCallback");
    }

    /*
     *  The jobTermination transfer the termination signal to workers in asynchronous way
     */
    private void jobTermination(String jobId) {
        try {
            PasswordCrackerWorkerService.AsyncClient worker = null;
            for (String workerAddress : workersAddressList) { // workersAddressList contains all the workers, not just 
                worker = new PasswordCrackerWorkerService.
                        AsyncClient(new TBinaryProtocol.Factory(), new TAsyncClientManager(), new TNonblockingSocket(workerAddress, WORKER_PORT));
                /** COMPLETE **/
                worker.reportTermination(jobId, new AsyncMethodCallback<PasswordCrackerWorkerService.AsyncClient.reportTermination_call>(){
                	public void onComplete(PasswordCrackerWorkerService.AsyncClient.reportTermination_call empty) {}
                    public void onError(Exception e) {}
                });
            }
        }
        catch (TException e) {
            e.printStackTrace();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}
