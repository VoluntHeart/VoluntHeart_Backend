package dev.webProject.VoluntHeart.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import dev.webProject.VoluntHeart.Models.LikeModel;

@Repository
public interface LikeRepo extends MongoRepository<LikeModel, String> {

    public LikeModel findByUserIdAndLikedPostId(String userId, String likedPostId);

}
