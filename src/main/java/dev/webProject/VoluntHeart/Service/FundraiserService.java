package dev.webProject.VoluntHeart.Service;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import dev.webProject.VoluntHeart.Models.Users.FundraiserModel;
import dev.webProject.VoluntHeart.Repository.FundraiserRepo;

@Service
public class FundraiserService {

    @Autowired
    FundraiserRepo fundraiserRepo;


    public List<FundraiserModel> getAll(){
        return fundraiserRepo.findAll();
    }

    public FundraiserModel findByEmail(String email){
        return fundraiserRepo.findByEmail(email);
    }



//update profile
    public FundraiserModel updateUser(String email, FundraiserModel requester){
       
        FundraiserModel fundraiser = findByEmail(email);

        if (requester.getFullName()!=null) {
            fundraiser.setFullName(requester.getFullName());
        }
        if (requester.getWebsite()!=null) {
            fundraiser.setWebsite(requester.getWebsite());
        }
        if (requester.getAbout()!=null) {
            fundraiser.setAbout(requester.getAbout());
        }
        if (requester.getMobile()!=null) {
            fundraiser.setMobile(requester.getMobile());
        }
        if (requester.getProfilePic()!=null) {
            fundraiser.setProfilePic(requester.getProfilePic());
        }
        if (requester.getCoverImage()!=null) {
            fundraiser.setCoverImage(requester.getCoverImage());
        }
        if (requester.getUserLocation()!=null) {
            fundraiser.setUserLocation(requester.getUserLocation());
        }

        return fundraiserRepo.save(fundraiser);
    }
    
}
